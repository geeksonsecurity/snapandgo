package fuzzing

import (
	"log"
	"time"
)

// Stats hold fuzzing statistics
type Stats struct {
	//sync.Mutex
	IterationCount   uint64
	CorpusLength     int
	TotalBreakpoints int
	FoundBreakpoints int
	Crashes          int

	startTime time.Time
}

// StatsMonitor print updates about the stats
func (s *Stats) StatsMonitor() {
	log.Printf("Initialized stats goroutine")
	s.startTime = time.Now()
	for {
		elapsed := time.Since(s.startTime)
		log.Printf("[%10.4f] cases %10d | fcps %8.4f | cov %2.1f%% (hit: %3d, tot: %3d) | corpus: %d | crashes: %d", elapsed.Seconds(), s.IterationCount, float64(s.IterationCount)/elapsed.Seconds(), float64(s.FoundBreakpoints)/float64(s.TotalBreakpoints)*100.0, s.FoundBreakpoints, s.TotalBreakpoints, s.CorpusLength, s.Crashes)
		time.Sleep(500 * time.Millisecond)
	}
}
