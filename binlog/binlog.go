package binlog

import "fmt"

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
		fmt.Printf("p = %+v\n", p)
		fmt.Printf("err = %+v\n", err)
		if err != nil || p == nil {
			return err
		} else {
			kp := p.(*OKPacket)
			c.getEventHeader(kp)
		}
	}
}

func (c *Conn) getEventHeader(p *OKPacket) {
	/*
		4              timestamp
		1              event type
		4              server-id
		4              event-size
		   if binlog-version > 1:
		4              log pos
		2              flags
	*/

	_ = c.getInt(TypeFixedInt, 4)

}
