(ns cryptopals.core
  (:require [clojure.string :refer [trim lower-case split]]
            [clojure.java.io :as io]
            [com.rpl.specter :refer [select transform ALL MAP-VALS MAP-KEYS]])
  (:import java.util.Base64))

; from https://stackoverflow.com/questions/10062967/clojures-equivalent-to-pythons-encodehex-and-decodehex
(defn unhexify "Convert hex string to byte sequence" [s]
  (letfn [(unhexify-2 [c1 c2]
            (unchecked-byte
              (+ (bit-shift-left (Character/digit c1 16) 4)
                 (Character/digit c2 16))))]
    (->> (partition 2 s)
         (map #(apply unhexify-2 %))
         (map byte)
         byte-array)))

; same
(defn hexify [bytes]
  (format "%x" (new BigInteger bytes)))

; "Cryptopals Rule:
; Always operate on raw bytes, never on encoded strings. Only use hex and base64 for pretty-printing."

(defn hex->base64
  [hex]
  (->> hex
       unhexify
       (.encodeToString (Base64/getEncoder))))

(defn bytes->str [bytes]
  (apply str (map char bytes)))

(defn fixed-xor
  [byte-array-1 byte-array-2]
  (byte-array (map bit-xor byte-array-1 byte-array-2)))

(def ENGLISH-CHARACTER-FREQUENCIES
  {\a 0.0855
   \b 0.016
   \c 0.0316
   \d 0.0387
   \e 0.121
   \f 0.0218
   \g 0.0209
   \h 0.0496
   \i 0.0733
   \j 0.0022
   \k 0.0081
   \l 0.0421
   \m 0.0253
   \n 0.0717
   \o 0.0747
   \p 0.0207
   \q 0.001
   \r 0.0633
   \s 0.0673
   \t 0.0894
   \u 0.0268
   \v 0.0106
   \w 0.0183
   \x 0.0019
   \y 0.0172
   \z 0.0011})

(defn chi-squared-score
  [expected observed]
  (apply +
         (for [[character expected-occurrences] expected]
           (do
             (/ (Math/pow (- expected-occurrences
                             (observed character 0))
                          2)
                expected-occurrences)))))

(defn score-string
  "Returns a number, 0 or greater, indicating how likely it is that `s` is some English text. Lower is better."
  [s]
  (let [expected (transform [MAP-VALS] #(* % (count s)) ENGLISH-CHARACTER-FREQUENCIES)
        observed (transform [MAP-KEYS] #(first (seq (lower-case %))) (frequencies s))
        okay-symbols #"[! .,;'\"\(\)]"
        unrecognized (filter #(and
                                (not (Character/isLetterOrDigit %))
                                (not (re-seq okay-symbols (str %))))
                             s)]
    (/ (+ (chi-squared-score expected observed)
          ; xxxxx is this right? i think i should get rid of the first item of this *
          (* (count unrecognized)
             (/ (count unrecognized)
                (count s))
             10))
       (count s))))

(defn attempt-to-decode-single-xored-bytes
  [byte-arr character]
  (let [character-buffer (byte-array (repeat (count byte-arr) character))
        xored-bytes (fixed-xor byte-arr character-buffer)]
    (when (every? nat-int? xored-bytes)
      [(char character)
       (bytes->str xored-bytes)
       (score-string (bytes->str xored-bytes))])))

(defn detect-single-character-xor
  [byte-arr]
  (let [decode-attempts (->> "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                             (map byte)
                             (map #(attempt-to-decode-single-xored-bytes byte-arr %)))
        valid-attempts (filter identity decode-attempts)]

    (second (first (sort-by
                     #(nth % 2)
                     valid-attempts))))
  ; TODO - return nil if none detected!!!!! filter for only scores < 1
  )


(comment
  (detect-single-character-xor (unhexify "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))

  (unhexify (first (split (slurp (io/resource "set_1_challenge_4.txt")) #"\n")))

  (let [inputs (split (slurp (io/resource "set_1_challenge_4.txt")) #"\n")]
    (filter identity (map #(detect-single-character-xor (unhexify %))
                          inputs)))


  )