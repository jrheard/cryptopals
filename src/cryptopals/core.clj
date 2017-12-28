(ns cryptopals.core
  (:require [clojure.spec.alpha :as s]
            [clojure.string :refer [trim lower-case split]]
            [clojure.java.io :as io]
            [com.rpl.specter :refer [select transform ALL MAP-VALS MAP-KEYS FIRST]])
  (:import java.util.Base64
           (javax.crypto Cipher)
           (javax.crypto.spec SecretKeySpec)))

;;;;;;;;;;;;
;; Utilities

(defn duplicates [xs]
  (for [[k v] (frequencies xs)
        :when (> v 1)]
    [k v]))

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

(defn pkcs7-pad [bytes block-length]
  (let [num-bytes-to-pad (- block-length
                            (rem (count bytes) block-length))]
    (concat bytes
            (repeat num-bytes-to-pad num-bytes-to-pad))))

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
  (let [partitioned (partition 16 ciphertext-bytes)
        xor-blocks (concat [iv-bytes] (drop-last 1 partitioned))
        decryption (apply concat
                          (reduce (fn [plaintext-bytes [block xor-block]]
                                    (conj plaintext-bytes
                                          ; Per https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_(CBC) :
                                          ; If you're decrypting, decrypt the block and _then_ xor it.
                                          (fixed-xor (aes-ecb-decrypt block key-bytes)
                                                     xor-block)))
                                  []
                                  (map vector partitioned xor-blocks)))
        padding-byte (last decryption)]
    (drop-last padding-byte decryption)))

(defn generate-aes-key []
  ; "Write a function to generate a random AES key; that's just 16 random bytes."
  (byte-array (take 16 (repeatedly #(rand-int 256)))))

; "Write a function that encrypts data under an unknown key --- that is,
; a function that generates a random key and encrypts under it."
(defn aes-encrypt-with-random-key-and-padding
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

(comment

  (let [key (generate-aes-key)
        bytes-to-append (base64->bytes "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")

        encrypt-fn #(aes-ecb-encrypt (pkcs7-pad (concat % bytes-to-append)
                                                16)
                                     key)

        cipher-block-size (discover-cipher-block-size encrypt-fn)]

    (assert (= cipher-block-size 16))
    (assert (does-cipher-use-ecb-mode? encrypt-fn))

    (loop [decoded-bytes-from-previous-blocks []
           decoded-bytes-from-this-block []
           block-num 0
           ; 15 As
           too-short-input (vec (repeat (dec cipher-block-size) (int \A)))]

      (let [plaintext-base (vec (concat decoded-bytes-from-previous-blocks
                                        too-short-input))

            ciphertext (take cipher-block-size
                             (drop (* block-num cipher-block-size)
                                   (map int
                                        (encrypt-fn (byte-array plaintext-base)))))

            encryptions-map (into {}
                                  (for [i (conj (range 32 122) 10)]
                                    [(take cipher-block-size
                                           (drop (* block-num cipher-block-size)
                                                 (map int
                                                      (encrypt-fn (byte-array (concat plaintext-base
                                                                                      decoded-bytes-from-this-block
                                                                                      [i]))))))
                                     i]))

            decoded-byte (encryptions-map ciphertext)]

        ; TODO - how do we know when we're done?
        ; when it starts to pkcs7-pad, i guess!

        (println decoded-byte)

        (if (= (count too-short-input) 0)
          (recur (concat decoded-bytes-from-previous-blocks decoded-bytes-from-this-block [decoded-byte])
                 []
                 (inc block-num)
                 (vec (repeat (dec cipher-block-size) (int \A))))

          (recur decoded-bytes-from-previous-blocks
                 (conj decoded-bytes-from-this-block decoded-byte)
                 block-num
                 (rest too-short-input))))))

  )
