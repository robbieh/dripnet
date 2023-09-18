#!/usr/bin/env bb
;lsof -i -sTCP:ESTABLISHED -n -F n 
;ASNI codes: https://gist.github.com/fnky/458719343aabd01cfb17a3a4f7296797

(require '[babashka.process :as p :refer [process destroy-tree]])
(require '[clojure.java.io :as io])
(require '[clojure.string :refer [split]])
(require '[clojure.core.async :as a])
(def esc (char 27))
(def home (char 13))
(def cls (str esc "[2J"))
(def mtl (str esc "[;H")) ;move top left
(def cursor-off (str esc "[?25l"))
(def cursor-on (str esc "[?25h"))
;what are 1049h and 1040l? not working in Konsole?
(def altmode-on (str esc "[?1048"))
(def altmode-off (str esc "[?1049"))

(def green42 (str esc "[38;5;42m"))
(def green82 (str esc "[38;5;83m"))
(def resetcolor (str esc "[0m"))

;(def dropchars["⋅" "○" "⊙" "◎" "⊚" "●"])
(def dropchars["⋅" "○" "◎" "●"])

(defn pos [x y]
  (str esc "[" y ";" x "H"))

(defn color256 [i]
  (str esc "[38;5;" i "m"))

(declare COLS)
(declare LINES)
(if (empty? *command-line-args*)
  (do (def COLS 80) (def LINES 24)) 
  (let [[c l] (take 2 *command-line-args*)]
    (def COLS (read-string c))
    (def LINES (read-string l))))

(defn cols [] COLS)
(defn lines [] LINES)

(def dropmatrix (ref []))
(def maxport 65535)
(def lmax (Math/log maxport))
(def scaling (/ (cols) lmax))

; tcpdump -------------------------------------------------------------------------
(def tcpdump-matches (ref []))

;16:31:18.577179 enp4s0 Out IP 192.168.2.101.58886 > 192.168.2.112.443: tcp 0
(defn tcpdump-parse-line [s]
  (let [[ts iface dir _ src _ dest proto _] (split s #" ")
        [_ _ _ _ destport]                  (split dest #"\.") 
        ]
    (when (= "Out" dir) (read-string destport))))

(def tcpdump-stream 
  (process {:err :inherit
            :shutdown destroy-tree}
          "sudo tcpdump -l -qn -iany '((tcp[tcpflags] & tcp-syn) != 0 or (ip6 and (ip6[13 + 40] & 2) == 2))'" ))

(def tcpdump-future 
  (future (with-open [rdr (io/reader (:out tcpdump-stream))]
            (binding [*in* rdr]
              ;(while (nil? (:exit tcpdump-stream))
              (loop []
                (when-let [line (read-line)]
                  ;(swap! tcpdump-matches (comp vec #(remove nil? %) conj) (tcpdump-parse-line line))
                  (dosync (alter tcpdump-matches (comp vec #(remove nil? %) conj) (tcpdump-parse-line line)))
                  (recur)
                  ))))))

(comment (identity @tcpdump-matches)
         (realized? tcpdump-future)
         (p/destroy-tree tcpdump-stream))

; output --------------------------------------------------------------------------
(defn bucket [i] (int (Math/ceil (* scaling (Math/log i)))))

(defn ports-to-drops [portlist]
  (let [f (frequencies portlist)]
    (map (fn [[x c]]
            (hash-map :x (bucket x) :y 1 :c (nth dropchars (dec c) "●") ))
          f)))

(defn move-drops [drops]
  (vec (remove nil? 
            (for [drop drops]
              (let [y (:y drop)]
                (if (< y (dec (lines)))
                  (assoc drop :y (inc y))))))))

(defn move-and-add-drops! []
  (dosync 
    (let [new (ports-to-drops @tcpdump-matches)]
      (ref-set tcpdump-matches [])
      (alter dropmatrix move-drops)
      (alter dropmatrix concat new))))

(defn print-background []
  (let [cols (cols)
        lines (lines)
        row (apply str (repeat cols "|"))]
    (print cls)
    ;(print green42)
    (doseq [x (repeat lines 1)]
      ;(doall (repeatedly lines (do (print row) (print "\r") (print "\n") (print (str esc "[#B")))))
      ;(print row) (print "\r") (print "\n") (print (str esc "[#B"))
      (println row) )
    (print resetcolor)
    ))

(defn print-drops []
  (doseq [{:keys [x y c p]} @dropmatrix]
    (println (str (pos x y) c))))

(defn cycle []
    (move-and-add-drops!)
    (print cls)
    (print mtl)
    ;(print-background)
    (print-drops))

(defn dripnet []
  (print cursor-off)
  (print altmode-on)
  (dotimes [i 600]
    (print mtl)
    (cycle)
    (Thread/sleep 250)
    )
  (print altmode-off)
  (print cursor-on))

(.addShutdownHook (Runtime/getRuntime) (Thread. (fn [] (println (str altmode-off cursor-on)))))

(println (cols) (lines))
(dripnet)

