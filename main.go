package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/miekg/pcap"
)

var ifn *string = flag.String("ifn", "", "input file name")
var ofn *string = flag.String("ofn", "", "output file name")

var isi *string = flag.String("isi", "", "input src IP")
var idi *string = flag.String("idi", "", "input dst IP")

var osi *string = flag.String("osi", "", "output src IP")
var odi *string = flag.String("odi", "", "output dst IP")

var ita *string = flag.String("ita", "", "input text array")
var ota *string = flag.String("ota", "", "output text array")

var ctn *bool = flag.Bool("ctn", true, "change time now")
var dbg *bool = flag.Bool("dbg", false, "debug")

func fatalIfErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	flag.Parse()
	f, err := os.Open(*ifn)
	fatalIfErr(err)
	defer f.Close()

	reader, err := pcap.NewReader(bufio.NewReader(f))
	fatalIfErr(err)

	if *ofn == "" {
		*ofn = "edcap_" + *ifn
	}

	w, err := os.Create(*ofn)
	fatalIfErr(err)
	defer w.Close()

	buf := bufio.NewWriter(w)
	writer, err := pcap.NewWriter(buf, &reader.Header)
	fatalIfErr(err)

	itaStrings := strings.Split(*ita, ",")
	otaStrings := strings.Split(*ota, ",")

	lIta := len(itaStrings)
	lOta := len(otaStrings)

	if lIta != lOta {
		fatalIfErr(fmt.Errorf("ita length(%d) needs to be the same as ota length(%d)", lIta, lOta))
	}

	var replaceStrings []string
	for i := 0; i < (lIta+lOta)/2; i++ {
		replaceStrings = append(replaceStrings, itaStrings[i])
		replaceStrings = append(replaceStrings, otaStrings[i])
	}

	replacer := strings.NewReplacer(replaceStrings...)
	isiBytes := stringByte(*isi)
	idiBytes := stringByte(*idi)
	osiBytes := stringByte(*osi)
	odiBytes := stringByte(*odi)

	for {
		pkt := reader.Next()
		if pkt == nil {
			break
		}
		if *isi != "" && *osi != "" && bytes.Contains(pkt.Data, isiBytes) {
			pkt.Data = bytes.Replace(pkt.Data, isiBytes, osiBytes, -1)
			if *dbg {
				log.Printf("replace %s with %s", *isi, *osi)
			}
		}
		if *idi != "" && *odi != "" && bytes.Contains(pkt.Data, idiBytes) {
			pkt.Data = bytes.Replace(pkt.Data, idiBytes, odiBytes, -1)
			if *dbg {
				log.Printf("replace %s with %s", *idi, *odi)
			}
		}
		if *ita != "" || *ota != "" {
			pkt.Data = []byte(replacer.Replace(string(pkt.Data)))
			pkt.Len = uint32(len(pkt.Data))
			pkt.Caplen = uint32(len(pkt.Data))
		}
		if *ctn {
			pkt.Time = time.Now()
		}
		if *dbg {
			err := pkt.Decode()
			fatalIfErr(err)
			log.Println(pkt.String())
			log.Println(string(pkt.Payload))
		}
		writer.Write(pkt)
	}
	buf.Flush()
}

const hexDigit = "0123456789abcdef"

func hexByte(s string) []byte {
	var b net.IP
	if strings.Contains(s, ":") {
		b = net.ParseIP(s).To16()
	} else {
		b = net.ParseIP(s).To4()
	}

	h := make([]byte, len(b)*2)
	for i, tn := range b {
		h[i*2], h[i*2+1] = hexDigit[tn>>4], hexDigit[tn&0xf]
	}
	return h
}

func stringByte(s string) []byte {
	var b net.IP
	if strings.Contains(s, ":") {
		b = net.ParseIP(s).To16()
	} else {
		b = net.ParseIP(s).To4()
	}
	return []byte(b)
}
