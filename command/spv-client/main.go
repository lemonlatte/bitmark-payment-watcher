package main

import (
	"flag"
	"os"
	"os/signal"
	"time"

	"github.com/bitmark-inc/exitwithstatus"
	"github.com/bitmark-inc/logger"
	"github.com/bitmark-inc/spv-client"
)

func main() {
	address := ""

	flag.StringVar(&address, "addr", "", "bitcoin address")
	flag.Parse()

	logConf := logger.Configuration{
		Directory: "log",
		File:      "payment-watcher.log",
		Count:     10,
		Size:      1024000,
		Levels:    map[string]string{logger.DefaultTag: "debug"},
		Console:   true,
	}

	if err := logger.Initialise(logConf); err != nil {
		exitwithstatus.Message(err.Error())
	}
	defer logger.Finalise()

	log := logger.New("main")

	w := payment.NewPaymentWatcher(payment.LtcTestNet4Params)
	if err := w.Start(address); err != nil {
		exitwithstatus.Message(err.Error())
	}

	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)

		for {
			<-c
			log.Info("Terminating process")
			w.Stop()
		}
	}()

	<-w.StopChan()
	log.Info("Process stopped")
}
