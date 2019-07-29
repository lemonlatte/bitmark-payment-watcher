package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/bitmark-inc/spv-client"
)

func main() {
	address := ""

	flag.StringVar(&address, "addr", "", "bitcoin address")
	flag.Parse()

	w := payment.NewPaymentWatcher(payment.LtcTestNet4Params)
	w.Start(address)

	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)

		for {
			<-c
			log.Println("Stopping process")
			w.Stop()
		}
	}()

	<-w.StopChan()
}
