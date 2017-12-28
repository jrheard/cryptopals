(ns cryptopals.core
  (:require [clojure.spec.alpha :as s]
            [clojure.string :refer [trim lower-case split]]
            [clojure.java.io :as io]
            [com.rpl.specter :refer [select transform ALL MAP-VALS MAP-KEYS FIRST]])
  (:import java.util.Base64
           (javax.crypto Cipher)
           (javax.crypto.spec SecretKeySpec)))

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

(defn bytes->str [bytes]
  (apply str (map char bytes)))

(defn parse-base64-file
  [filename]
  (as-> filename $
        (io/resource $)
        (slurp $)
        (clojure.string/replace $ #"\n" "")
        (.decode (Base64/getDecoder) $)))

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

    (ffirst (sort-by second key-sizes-and-distances))))

(defn repeating-key-xor-decrypt
  ([ciphertext-bytes]
    ; "The KEYSIZE with the smallest normalized edit distance is probably the key."
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

; Write a function that encrypts data under an unknown key --- that is,
; a function that generates a random key and encrypts under it.
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


(comment
  (rand-int 6)

  (println (map int (aes-encrypt-with-random-key-and-padding (.getBytes "the key is under the flowerpot"))))

  )
