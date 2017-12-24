(ns cryptopals.core-test
  (:require [clojure.test :refer :all]
            [cryptopals.core :refer :all]))

(deftest set-1-challenge-1
  (is (= (hex->base64 "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
         "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")))

(deftest set-1-challenge-2
  (is (= (hexify (fixed-xor (unhexify "1c0111001f010100061a024b53535009181c")
                            (unhexify "686974207468652062756c6c277320657965")))
         "746865206b696420646f6e277420706c6179")))


(deftest set-1-challenge-3
  (let [input (unhexify "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")]
    (is (= (second (first (sort-by
                            #(nth % 2)
                            (for [character (map byte "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")]
                              (let [character-buffer (byte-array (repeat (count input) character))
                                    decoded (bytes->str (fixed-xor input character-buffer))]
                                [(char character)
                                 decoded
                                 (score-string decoded)])))))
           "Cooking MC's like a pound of bacon"))))
