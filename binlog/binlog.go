package binlog

import (
	"fmt"
)

func (c *Conn) registerAsSlave() error {
	brsc := &BinlogRegisterSlaveCommand{
		Status:   COMMAND_REGISTER_SLAVE,
		ServerId: c.Config.ServerId,
		Hostname: "",
		User:     "",
		Password: "",
		Port:     0,
		ReplRank: 0,
		MasterId: 0,
	}

	return c.writeBinlogRegisterSlaveCommand(brsc)
}

func (c *Conn) startBinlogStream() error {
	bldc := &BinlogDumpCommand{
		Status:   COMMAND_BIN_LOG_DUMP,
		Position: 120,
		Flags:    BINLOG_DUMP_NON_BLOCK,
		ServerId: c.Config.ServerId,
		Filename: c.Config.BinlogFile,
	}

	return c.writeBinlogDumpCommand(bldc)
}

func (c *Conn) listenForBinlog() error {
	for {
		p, err := c.readPacket()
		if err != nil {
			if err.Error() == "EOF" {
				continue
			} else {
				return err
			}
		} else {
			kp := p.(*OKPacket)
			fmt.Printf("kp = %+v\n", kp)
		}
	}

	return nil
}
