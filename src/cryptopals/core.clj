(ns cryptopals.core
  (:require [clojure.spec.alpha :as s]
            [clojure.string :refer [trim lower-case split]]
            [clojure.java.io :as io]
            [com.rpl.specter :refer [select transform ALL MAP-VALS MAP-KEYS]])
  (:import java.util.Base64))

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
                             s)]

    (/ (+ (chi-squared-score expected observed)
          (/ (* (count unrecognized)
                (count unrecognized)
                200)
             (count s)))
       (count s))))

(re-seq #"[:]" "foo:")

(defn attempt-to-decode-single-xored-bytes
  [bytes character]
  (let [character-buffer (repeat (count bytes) character)
        xored-bytes (fixed-xor bytes character-buffer)]

    [(char character)
     (bytes->str xored-bytes)
     (score-string (bytes->str xored-bytes))]))

(s/fdef attempt-to-decode-single-xored-bytes
  :ret (s/? (s/tuple char? string? number?)))

(defn detect-single-character-xor
  [byte-arr]
  (let [decode-attempts (->> (map int "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
                             (map #(attempt-to-decode-single-xored-bytes byte-arr %)))
        valid-attempts (filter #(< (nth % 2) 1) decode-attempts)]

    (second (first (sort-by
                     #(nth % 2)
                     valid-attempts)))))

(defn repeating-key-xor-encrypt
  [plaintext-bytes key-bytes]
  (map bit-xor plaintext-bytes (cycle key-bytes)))


(defn hamming-distance
  [a b]
  (assert (= (count a) (count b)))

  (count (filter #(= % \1)
                 (mapcat #(Integer/toString % 2)
                         (map bit-xor a b)))))



(comment

  (let [inputs (split (slurp (io/resource "set_1_challenge_4.txt")) #"\n")]
    (first (filter identity (map #(detect-single-character-xor (unhexify %))
                                 inputs))))

  (count (slurp (io/resource "set_1_challenge_4.txt")))

  (count (clojure.string/replace (slurp (io/resource "set_1_challenge_4.txt")) #"\n" ""))

  (let [input (slurp (io/resource "set_1_challenge_4.txt"))]

    input
    )

  )