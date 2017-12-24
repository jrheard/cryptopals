(ns cryptopals.core
  (:require [clojure.string :refer [trim]]
            [com.rpl.specter :refer [select transform ALL MAP-VALS]])
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

(defn score-string
  "Returns a number between 0.0 and 1.0, indicating how likely it is that `s` is some English text."
  [s]
  (let [letters (filter #(Character/isLetter %) s)
        lowercase-letters (filter #(Character/isLowerCase %) s)
        digits (filter #(Character/isDigit %) s)
        normal-sentence-symbols-re #"[!@., ;:\(\)'\"]"
        normal-sentence-symbols (re-seq normal-sentence-symbols-re s)

        everything-else (filter #(not
                                   (or
                                     (Character/isLetter %)
                                     (Character/isDigit %)
                                     (re-seq normal-sentence-symbols-re (str %))))
                                s)

        scores [(- 0.8
                   (/ (count letters) (count s)))
                (- 0.9
                   (/ (count lowercase-letters) (count letters)))
                (- 0.2
                   (/ (+ (count digits) (count normal-sentence-symbols))
                      (count s)))
                (/ (count everything-else) (count s))]]

    (- 1
       (/ (apply +
                 (for [score scores]
                   (min (Math/abs (float score)) 1)))
          (count scores)))))

(comment

  (let [foo (unhexify "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")]
    (for [character (map byte "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")]
      (let [character-buffer (byte-array (repeat (count foo) character))
            decoded (bytes->str (fixed-xor foo character-buffer))]
        [(char character)
         decoded
         (score-string decoded)])))

  (Integer/toString (int \X) 2)
  (int \X)

  (let [foo "Cooking MC's like a pound of bacon"
        bar (frequencies foo)]
    (filter #(Character/isLowerCase %) foo)
    )

  )