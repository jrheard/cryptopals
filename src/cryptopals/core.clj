(ns cryptopals.core
  (:require [clojure.set :refer [map-invert]]
            [clojure.spec.alpha :as s]
            [clojure.string :refer [trim lower-case split]]
            [clojure.java.io :as io]
            [com.rpl.specter :refer [select transform ALL MAP-VALS MAP-KEYS FIRST INDEXED-VALS collect-one LAST]]
            [ring.util.codec :as codec])
  (:import java.util.Base64
           (javax.crypto Cipher)
           (javax.crypto.spec SecretKeySpec)))

;;;;;;;;;;;;
;; Utilities

(defn duplicates [xs]
  (for [[k v] (frequencies xs)
        :when (> v 1)]
    [k v]))

(defn index-of-first-truthy-item
  ([xs]
   (index-of-first-truthy-item xs 0))
  ([xs curr-index]
   (cond
     (not (seq xs)) -1
     (first xs) curr-index
     :else (index-of-first-truthy-item (rest xs) (inc curr-index)))))


; from https://stackoverflow.com/questions/10062967/clojures-equivalent-to-pythons-encodehex-and-decodehex
(defn unhexify [s]
  (map
    (fn [[x y]] (Integer/parseInt (str x y) 16))
    (partition 2 s)))

; same
(defn hexify [bytes]
  (format "%x" (new BigInteger (byte-array bytes))))

; "Cryptopals Rule:
; Always operate on raw bytes, never on encoded strings. Only use hex and base64 for pretty-printing."

(defn hex->base64
  [hex]
  (->> hex
       unhexify
       byte-array
       (.encodeToString (Base64/getEncoder))))

(defn base64->bytes
  [base64]
  (.decode (Base64/getDecoder) base64))

(defn bytes->str [bytes]
  (apply str (map char bytes)))

(defn parse-base64-file
  [filename]
  (as-> filename $
        (io/resource $)
        (slurp $)
        (clojure.string/replace $ #"\n" "")
        (base64->bytes $)))

(defn fixed-xor
  [xs ys]
  (assert (= (count xs) (count ys)))
  (map bit-xor xs ys))

; http://www.macfreek.nl/memory/Letter_Distribution
(def ENGLISH-CHARACTER-FREQUENCIES
  {\a     0.06532
   \b     0.016
   \c     0.0316
   \d     0.0328
   \e     0.1027
   \f     0.0218
   \g     0.0209
   \h     0.0496
   \i     0.0566
   \j     0.0022
   \k     0.0081
   \l     0.0331
   \m     0.0253
   \n     0.0571
   \o     0.06159
   \p     0.0207
   \q     0.001
   \r     0.0498
   \s     0.0531
   \t     0.0751
   \u     0.0268
   \v     0.0106
   \w     0.0183
   \x     0.0019
   \y     0.0172
   \z     0.0011
   \space 0.18})

(defn chi-squared-score
  [expected observed]
  (apply +
         (for [[character expected-occurrences] expected]
           (/ (Math/pow (- expected-occurrences
                           (observed character 0))
                        2)
              expected-occurrences))))

(defn score-string
  "Returns a number, 0 or greater, indicating how likely it is that `s` is some English text. Lower is better."
  [s]
  (let [expected (transform [MAP-VALS] #(* % (count s)) ENGLISH-CHARACTER-FREQUENCIES)
        observed (transform [MAP-KEYS] #(first (seq (lower-case %))) (frequencies s))
        okay-symbols #"[!? .,;\:\-'\"\(\)\n]"
        unrecognized (filter #(and
                                (not (Character/isLetterOrDigit %))
                                (not (re-seq okay-symbols (str %))))
                             s)
        awful (filter #(not (or (= (int %) 10)
                                (<= 32 (int %) 122)))
                      s)]

    (/ (+ (chi-squared-score expected observed)
          (if (seq awful) 10000 0)
          (/ (* (count unrecognized)
                (count unrecognized)
                500)
             (count s)))
       (count s))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Nonstandard encryption/decryption functions from set 1

(defn attempt-to-decode-single-xored-bytes
  [bytes character]
  (let [character-buffer (repeat (count bytes) character)
        xored-bytes (fixed-xor bytes character-buffer)]

    [(char character)
     (bytes->str xored-bytes)
     (score-string (bytes->str xored-bytes))]))

(s/fdef attempt-to-decode-single-xored-bytes
  :ret (s/? (s/tuple char? string? number?)))

(def MAGIC-SINGLE-XOR-DETECTION-STRING-SCORE-THRESHOLD 10)

(defn detect-single-character-xor
  [byte-arr]
  (let [decode-attempts (->> (range 32 123)
                             (map #(attempt-to-decode-single-xored-bytes byte-arr %)))
        valid-attempts (filter #(< (nth % 2) MAGIC-SINGLE-XOR-DETECTION-STRING-SCORE-THRESHOLD)
                               decode-attempts)
        highest-scorer (first (sort-by #(nth % 2)
                                       valid-attempts))]

    (when highest-scorer
      (vec (take 2 highest-scorer)))))

(defn repeating-key-xor-encrypt
  [plaintext-bytes key-bytes]
  (map bit-xor plaintext-bytes (cycle key-bytes)))

(defn hamming-distance
  [a b]
  (assert (= (count a) (count b)))

  ; "The Hamming distance is just the number of differing bits."
  (count (filter #(= % \1)
                 (mapcat #(Integer/toString % 2)
                         (map bit-xor a b)))))

(defn detect-repeating-xor-keysize
  [ciphertext-bytes]
  ; "Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40."
  (let [key-sizes-and-distances (for [key-size (range 2 41)]
                                  ; "For each KEYSIZE, take the first KEYSIZE worth of bytes, and
                                  ; the second KEYSIZE worth of bytes, and find the edit distance
                                  ; between them."
                                  ;
                                  ; I found that this advice didn't give workable results, so I take the average
                                  ; edit distance between _all_ of the chunks in the ciphertext.
                                  (let [chunks (partition key-size ciphertext-bytes)
                                        distances (map hamming-distance chunks (rest chunks))
                                        mean-distance (/ (apply + distances) (count distances))]

                                    [key-size
                                     ; "Normalize this result by dividing by KEYSIZE."
                                     (float (/ mean-distance key-size))]))]

    ; "The KEYSIZE with the smallest normalized edit distance is probably the key."
    (ffirst (sort-by second key-sizes-and-distances))))

(defn repeating-key-xor-decrypt
  ([ciphertext-bytes]
   (repeating-key-xor-decrypt ciphertext-bytes (detect-repeating-xor-keysize ciphertext-bytes)))

  ([ciphertext-bytes key-size]
    ; "Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length."
   (let [chunked-ciphertext (map (partial apply vector)
                                 (partition key-size ciphertext-bytes))

         ; "Now transpose the blocks: make a block that is the first byte of every block,
         ; and a block that is the second byte of every block, and so on."
         transposed-blocks (for [i (range key-size)]
                             (select [ALL i] chunked-ciphertext))

         ; "Solve each block as if it was single-character XOR. You already have code to do this."
         decodings (map detect-single-character-xor transposed-blocks)

         key (map first decodings)]

     ; "For each block, the single-byte XOR key that produces the best looking histogram
     ; is the repeating-key XOR key byte for that block. Put them together and you have the key."
     [key
      (map bit-xor
           ciphertext-bytes
           (take (count ciphertext-bytes)
                 (cycle (map int key))))])))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; AES encryption/decryption

(defn aes-ecb [mode bytes key-bytes]
  (let [key (SecretKeySpec. key-bytes "AES")
        cipher (Cipher/getInstance "AES/ECB/NoPadding")]

    (.init cipher mode key)
    (->> bytes
         byte-array
         (.doFinal cipher))))

(def aes-ecb-decrypt (partial aes-ecb (Cipher/DECRYPT_MODE)))
(def aes-ecb-encrypt (partial aes-ecb (Cipher/ENCRYPT_MODE)))

(defn pkcs7-pad
  [bytes block-length]
  (let [num-bytes-to-pad (- block-length
                            (rem (count bytes) block-length))]
    (concat bytes
            (repeat num-bytes-to-pad num-bytes-to-pad))))

(defn pkcs7-depad
  [bytes]
  (drop-last (last bytes) bytes))

(defn aes-cbc-encrypt
  ; "In CBC mode, each ciphertext block is added to the next plaintext block before the
  ; next call to the cipher core."
  [plaintext-bytes key-bytes iv-bytes]
  (apply concat
         (reduce (fn [ciphertext-bytes block]
                   (let [xor-block (if (seq ciphertext-bytes)
                                     (last ciphertext-bytes)
                                     iv-bytes)]
                     (conj ciphertext-bytes
                           ; Per https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_(CBC) :
                           ; When encrypting, xor on the way in and then encrypt.
                           (aes-ecb-encrypt (fixed-xor block xor-block)
                                            key-bytes))))
                 []
                 (partition 16 (pkcs7-pad plaintext-bytes 16)))))

(defn aes-cbc-decrypt
  [ciphertext-bytes key-bytes iv-bytes]
  (let [ciphertext-blocks (partition 16 ciphertext-bytes)
        xor-blocks (concat [iv-bytes] (drop-last 1 ciphertext-blocks))
        decryption (apply concat
                          (reduce (fn [plaintext-bytes [block xor-block]]
                                    (conj plaintext-bytes
                                          ; Per https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_(CBC) :
                                          ; If you're decrypting, decrypt the block and _then_ xor it.
                                          (fixed-xor (aes-ecb-decrypt block key-bytes)
                                                     xor-block)))
                                  []
                                  (map vector ciphertext-blocks xor-blocks)))]
    decryption))

(defn generate-aes-key []
  ; "Write a function to generate a random AES key; that's just 16 random bytes."
  (byte-array (take 16 (repeatedly #(rand-int 256)))))

(defn aes-encrypt-with-random-key-and-padding
  ; "Write a function that encrypts data under an unknown key --- that is,
  ; a function that generates a random key and encrypts under it."
  [bytes]
  (let [key (generate-aes-key)
        num-chars-to-prepend (+ 5 (rand-int 6))
        num-chars-to-append (+ 5 (rand-int 6))
        padded-bytes (concat (take num-chars-to-prepend (repeatedly #(rand-int 256)))
                             bytes
                             (take num-chars-to-append (repeatedly #(rand-int 256))))]
    (if (= 0 (rand-int 2))
      (aes-ecb-encrypt (pkcs7-pad padded-bytes 16) key)
      (aes-cbc-encrypt padded-bytes key (generate-aes-key)))))

(defn ciphertext-likely-encrypted-with-ecb-mode?
  [ciphertext-bytes]
  (let [chunks (partition 16 ciphertext-bytes)
        dupe-chunks (duplicates chunks)]
    (> (count dupe-chunks) 0)))

(defn discover-cipher-block-size
  [cipher-encrypt-fn]
  ; "Feed identical bytes of your-string to the function 1 at a time --- start with 1 byte ("A"),
  ; then "AA", then "AAA" and so on. Discover the block size of the cipher."
  (loop [i 1
         last-seen-ciphertext-size nil]
    (let [ciphertext (cipher-encrypt-fn (.getBytes (apply str (repeat i "A"))))]

      (if (and last-seen-ciphertext-size
               (not= (count ciphertext) last-seen-ciphertext-size))

        (- (count ciphertext) last-seen-ciphertext-size)
        (recur (inc i) (count ciphertext))))))

(defn does-cipher-use-ecb-mode?
  [cipher-encrypt-fn]
  ; cipher-encrypt-fn must be a one-argument function that takes ciphertext-bytes
  (ciphertext-likely-encrypted-with-ecb-mode?
    (cipher-encrypt-fn (.getBytes (apply str (repeat 300 "A"))))))

(defn detect-end-of-prepended-bytes
  [encrypt-fn]
  (let [block-size (discover-cipher-block-size encrypt-fn)

        ; Our goal is to discover the index of the first block at which our message begins,
        ; as well as the _offset_ within that block where any prepended bytes end and our message begins.
        ;
        ; To figure this out, we start by generating a message with two blocks' worth of As, and then
        ; adding one more A at at time until we get to three blocks' worth.
        ciphertexts (map #(partition block-size %)
                         (map encrypt-fn
                              (for [i (range (* 2 block-size)
                                             (* 3 block-size))]
                                (map int (repeat i \A)))))

        ; By the time we've generated a message with three blocks' worth of As, the ciphertext
        ; is guaranteed to contain at least two duplicate blocks. The first duplicate block
        ; will be the block _after_ the one where the prepended bytes end.
        ;
        ; (Unless there weren't any prepended bytes, in which case the 0th block of the ciphertext
        ; will be the first duplicate block. We'll handle that special case later.)
        index-of-first-duplicate-block (ffirst (select [INDEXED-VALS (collect-one FIRST) LAST
                                                        #(= (first %) (second %))]
                                                       (map vector
                                                            (last ciphertexts)
                                                            (rest (last ciphertexts)))))

        ; We can figure out the offset in that block where our message starts by
        ; figuring out how many As were necessary in order to create those two duplicate blocks.
        ;
        ; For instance, if we've got a block size of 8 and there were 5 bytes prepended in this block
        ; before our message begins, we'll see that we needed to generate (+ (* 2 block-size) 3) As
        ; before we started to see those two duplicate blocks in the ciphertext.
        ; (- 8 3) is 5, which is the offset in this block at which our message begins to appear.
        offset-where-message-begins (- block-size
                                       (index-of-first-truthy-item
                                         (for [ciphertext ciphertexts]
                                           (= (nth ciphertext index-of-first-duplicate-block)
                                              (nth ciphertext (inc index-of-first-duplicate-block))))))]

    (if (= offset-where-message-begins block-size)
      [index-of-first-duplicate-block 0]
      [(dec index-of-first-duplicate-block) offset-where-message-begins])))

(defn byte-at-a-time-ecb-decrypt
  [encrypt-fn]
  (let [cipher-block-size (discover-cipher-block-size encrypt-fn)
        [message-start-block message-start-offset] (detect-end-of-prepended-bytes encrypt-fn)]

    (loop [decoded-bytes-from-previous-blocks []
           decoded-bytes-from-this-block []
           block-num 0
           ; "Knowing the block size, craft an input block that is exactly 1 byte short
           ; (for instance, if the block size is 8 bytes, make "AAAAAAA"). Think about
           ; what the oracle function is going to put in that last byte position."
           too-short-input (vec (repeat (+ (dec cipher-block-size)
                                           ; We also add enough As to make sure that our message
                                           ; starts at the beginning of a fresh block. See 2.14.
                                           (if (> message-start-offset 0)
                                             (- cipher-block-size message-start-offset)
                                             0))
                                        (int \A)))]

      (let [bytes-to-drop (* (+ block-num
                                (if (> message-start-offset 0)
                                  (inc message-start-block)
                                  message-start-block))
                             cipher-block-size)

            get-relevant-block-of-ciphertext (fn [plaintext]
                                               (->> plaintext
                                                    byte-array
                                                    encrypt-fn
                                                    (map int)
                                                    (drop bytes-to-drop)
                                                    (take cipher-block-size)))

            ciphertext (get-relevant-block-of-ciphertext too-short-input)

            ; "Make a dictionary of every possible last byte by feeding different strings to the oracle;
            ; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC"."
            encryptions-map (into {}
                                  (for [i (conj (range 122) 10)]
                                    [(get-relevant-block-of-ciphertext
                                       (concat too-short-input
                                               decoded-bytes-from-previous-blocks
                                               decoded-bytes-from-this-block
                                               [i]))
                                     i]))

            ; "Match the output of the one-byte-short input to one of the entries in your dictionary."
            decoded-byte (encryptions-map ciphertext)]

        (if decoded-byte
          (if (= (count too-short-input) 0)
            ; We've reached the end of a block; add this block's bytes to
            ; decoded-bytes-from-previous-blocks and recur.
            (recur (concat decoded-bytes-from-previous-blocks decoded-bytes-from-this-block [decoded-byte])
                   []
                   (inc block-num)
                   (vec (repeat (dec cipher-block-size) (int \A))))

            ; Otherwise, record this decoded byte in decoded-bytes-from-this-block and recur.
            (recur decoded-bytes-from-previous-blocks
                   (conj decoded-bytes-from-this-block decoded-byte)
                   block-num
                   (vec (rest too-short-input))))

          ; If we couldn't decrypt this byte, we've reached a pkcs-7 padding byte and we're done!
          (concat decoded-bytes-from-previous-blocks decoded-bytes-from-this-block))))))

(defn decode-profile
  [profile-string]
  (codec/form-decode profile-string))

(defn encode-profile
  ; "Write a k=v parsing routine, as if for a structured cookie."
  [profile-map]
  (clojure.string/join "&"
                       (for [[k v] profile-map]
                         (str k "=" v))))

(defn profile-for
  ; "Now write a function that encodes a user profile in that format, given an email address."
  [email]
  ; "Your "profile_for" function should not allow encoding metacharacters (& and =).
  ; Eat them, quote them, whatever you want to do."
  (let [stripped-email (clojure.string/replace email #"[=&]" "")]
    {"email" stripped-email
     "uid"   10
     "role"  "user"}))

(defn is-padding-valid?
  [bytes block-size]
  (let [padding-byte (last bytes)]
    (and (= (rem (count bytes) block-size) 0)
         (<= 1 padding-byte block-size)
         (apply = (take-last padding-byte bytes)))))

(defn enforce-valid-padding
  ; "Write a function that takes a plaintext, determines if it has valid PKCS#7 padding,
  ; and strips the padding off.
  ; If you are writing in a language with exceptions, like Python or Ruby, make your
  ; function throw an exception on bad padding."
  [bytes block-size]
  (assert (is-padding-valid? bytes block-size))
  (pkcs7-depad bytes))

(def ESCAPE-CHARACTERS-2-16
  {\; "&#59;"
   \& "&#38;"})

(defn encrypt-comment-userdata-string
  ; "The first function should take an arbitrary input string, prepend the string:
  ; "comment1=cooking%20MCs;userdata="
  ; .. and append the string:
  ; ";comment2=%20like%20a%20pound%20of%20bacon"
  [userdata-string key iv]
  ; "The function should quote out the ";" and "=" characters."
  (let [message (str "comment1=cooking%20MCs;userdata="
                     (clojure.string/escape userdata-string ESCAPE-CHARACTERS-2-16)
                     ";comment2=%20like%20a%20pound%20of%20bacon")]
    ; "The function should then pad out the input to the 16-byte AES block length
    ; and encrypt it under the random AES key."
    (aes-cbc-encrypt (pkcs7-pad (.getBytes message) 16)
                     key
                     iv)))

(defn is-comment-by-admin?
  ; "The second function should decrypt the string and look for the characters ";admin=true;"
  ; Return true or false based on whether the string exists."
  [ciphertext-bytes key iv]
  (let [plaintext (as-> ciphertext-bytes $
                        (aes-cbc-decrypt $ key iv)
                        (enforce-valid-padding $ 16)
                        (map #(bit-and % 0xff) $)
                        (bytes->str $))]

    (boolean (re-seq #";admin=true;" plaintext))))

(defn random-string-3-17
  ; "The first function should select at random one of the following 10 strings."
  []
  (rand-nth (split "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=\nMDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=\nMDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==\nMDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==\nMDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl\nMDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==\nMDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==\nMDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=\nMDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=\nMDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
                   #"\n")))

(defn verify-ciphertext-3-17
  ; "The second function should consume the ciphertext produced by the first function,
  ; decrypt it, check its padding, and return true or false depending on whether the padding is valid."
  [ciphertext key iv]
  (is-padding-valid? (aes-cbc-decrypt ciphertext key iv) 16))

(comment
  (let [key (generate-aes-key)
        string (random-string-3-17)
        iv (byte-array (repeat 16 0))
        ciphertext (aes-cbc-encrypt (.getBytes string) key iv)]

    (verify-ciphertext-3-17 ciphertext key iv)

    )

  (random-string-3-17)

  )




