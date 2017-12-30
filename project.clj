(defproject cryptopals "0.1.0-SNAPSHOT"
  :description "FIXME: write description"
  :url "http://example.com/FIXME"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.9.0"]

                 [buddy "2.0.0"]
                 [com.rpl/specter "1.0.5"]
                 [org.clojure/core.match "0.3.0-alpha5"]
                 [ring/ring-core "1.6.3"]

                 [org.clojure/spec.alpha "0.1.143"]
                 [orchestra "2017.11.12-1"]]
  :main ^:skip-aot cryptopals.core
  :target-path "target/%s"
  :profiles {:uberjar {:aot :all}})
