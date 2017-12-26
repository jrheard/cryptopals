(ns cryptopals.core-test
  (:require [clojure.java.io :as io]
            [clojure.string :refer [split]]
            [clojure.test :refer :all]
            [cryptopals.core :refer :all]))

(deftest set-1-challenge-1
  (is (= (hex->base64 "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
         "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")))

(deftest set-1-challenge-2
  (is (= (hexify (fixed-xor (unhexify "1c0111001f010100061a024b53535009181c")
                            (unhexify "686974207468652062756c6c277320657965")))
         "746865206b696420646f6e277420706c6179")))

(deftest set-1-challenge-3
  (is (= (detect-single-character-xor (unhexify "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))
         "Cooking MC's like a pound of bacon")))

(deftest set-1-challenge-4
  (is (= (let [inputs (split (slurp (io/resource "set_1_challenge_4.txt")) #"\n")]
           (first (filter identity (map #(detect-single-character-xor (unhexify %))
                                        inputs))))
         "Now that the party is jumping\n")))

(deftest set-1-challenge-5
  (is (= (repeating-key-xor-encrypt (.getBytes "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
                                    (.getBytes "ICE"))
         (unhexify "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"))))
