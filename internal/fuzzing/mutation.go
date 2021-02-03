package fuzzing

import (
	"bytes"
	"log"
	"math/rand"
)

//Mutation handle simple mutation strategy
type Mutation struct {
	corpus [][]byte
	empty  []byte
	c      int
}

func (m *Mutation) clone(input []byte) []byte {
	newbuff := make([]byte, len(input))
	copy(newbuff, input)
	return newbuff
}
func (m *Mutation) storeCorpus(c []byte) bool {
	for _, x := range m.corpus {
		// compare on array with 0x0 values will stop comparing on first null (e.g. []{ 0x0, 0x0, 0x0 } == []{ 0x0, 0x0 })
		if bytes.Compare(x, c) == 0 {
			return false
		}
	}

	// messed up way to prevent string rendering strange stuff (aka prevent multiple line)
	var cleanedUp []byte
	for _, b := range c {
		if b > 0x20 && b < 0x7f {
			cleanedUp = append(cleanedUp, b)
		} else {
			cleanedUp = append(cleanedUp, 0xf0)
		}
	}
	log.Printf("[+] New corpus (preview): '%s'", string(cleanedUp))
	m.corpus = append(m.corpus, m.clone(c))
	return true
}

func (m *Mutation) pickCorpus() []byte {
	if len(m.corpus) == 0 {
		return m.empty
	}
	idx := rand.Int() % len(m.corpus)
	// If we dont clone here a reference is passed and the value inside the m.corpus array is modified! (in-place)
	return m.clone(m.corpus[idx])
}

// Init initialize corpus and default value
func (m *Mutation) Init() {
	m.empty = []byte{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x0}
	m.corpus = make([][]byte, 0)
	log.Printf("Corpus initialized %d items", len(m.corpus))
}

// Mutate return a mutation from a randomly selected item from the input queue
func (m *Mutation) Mutate() []byte {
	// get a corpus and mutate it
	tc := m.pickCorpus()

	index0 := rand.Intn(len(tc) - 1)
	byte0 := byte(rand.Uint32() % 256)
	index1 := rand.Intn(len(tc) - 1)
	byte1 := byte(rand.Uint32() % 256)

	tc[index0] = byte0
	tc[index1] = byte1

	//log.Printf("Mutation '%s'", hex.Dump(tc))

	// mutate
	/*
		t := rand.Intn(4)
		switch t {
		case 0: // append 1 random byte
			//fmt.Println("Mutation type: append")
			rb := rand.Intn(256)
			tc = append(tc, byte(rb))
		case 1: // flip bytes
			//fmt.Println("Mutation type: flip")
			tc = bytes.Replace(tc, []byte{tc[rand.Intn(len(tc))]}, []byte{tc[rand.Intn(len(tc))]}, 1)
		case 2: // remove 1 byte
			//fmt.Println("Mutation type: remove")
			tc = bytes.TrimPrefix(tc, []byte{tc[rand.Intn(len(tc))]})
		case 3: // random
			tc, _ = f.genBytes(uint64(rand.Intn(16)))
		}*/
	return tc
}
