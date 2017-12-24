(ns cryptopals.core
  (:require [clojure.string :refer [trim lower-case]]
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

(defn bytes->str
  [bytes]
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
    (+ (chi-squared-score expected observed)
       (* (count unrecognized)
          (/ (count unrecognized)
             (count s))
          10))))


(comment
  )