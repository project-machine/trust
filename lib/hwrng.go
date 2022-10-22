package lib

import (
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"github.com/apex/log"
	"github.com/pkg/errors"
)

func HWRNGPoolSize() (int, error) {
	const poolSizePath = "/proc/sys/kernel/random/poolsize"
	data, err := ioutil.ReadFile(poolSizePath)
	if err != nil {
		return -1, err
	}
	n, err := strconv.Atoi(strings.Trim(string(data), "\n"))
	if err != nil {
		return -1, err
	}
	// poolSize is bits, we want bytes.
	return n / 8, err
}

func HWRNGSeed() error {

	size, err := HWRNGPoolSize()
	if err != nil {
		return err
	}

	rndBytes, err := HWRNGRead(size)
	if err != nil {
		return err
	}

	wf, err := os.OpenFile("/dev/urandom", os.O_WRONLY, 0)
	if err != nil {
		log.Infof("failed to open /dev/urandom: %v", err)
		return err
	}
	defer wf.Close()

	if l, err := wf.Write(rndBytes); err != nil {
		return err
	} else if l != size {
		return errors.Errorf("Tried to write %d bytes random, but wrote %d", size, l)
	}

	return nil
}

func HWRNGRead(size int) ([]byte, error) {
	rf, err := os.Open("/dev/hwrng")
	if err != nil {
		return []byte{}, errors.Wrapf(err, "Failed opening hwrng")
	}
	defer rf.Close()
	buf := make([]byte, size)
	num, err := rf.Read(buf)
	if err != nil {
		return []byte{}, errors.Wrapf(err, "Failed reading random bytes")
	}

	if num != size {
		return []byte(buf), errors.Errorf("Read only %d bytes, wanted %d", num, size)
	}

	return []byte(buf), nil
}
