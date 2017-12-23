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

(defn bytes->str
  [bytes]
  (apply str (map char bytes)))

(defn fixed-xor
  [byte-array-1 byte-array-2]
  (byte-array (map bit-xor byte-array-1 byte-array-2)))


(comment

  (let [foo (unhexify "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")]
    (for [character (map byte "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")]
      (let [character-buffer (byte-array (repeat (count foo) character))]
        (bytes->str
          (fixed-xor foo character-buffer)
          )
        )


      )

    )

  )