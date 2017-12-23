(ns cryptopals.core
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

(defn fixed-xor
  [byte-array-1 byte-array-2]
  (byte-array (map bit-xor byte-array-1 byte-array-2)))


(comment
  (let [foo (unhexify "1c0111001f010100061a024b53535009181c")
        bar (unhexify "686974207468652062756c6c277320657965")]
    (hexify (fixed-xor foo bar))

    )

  )