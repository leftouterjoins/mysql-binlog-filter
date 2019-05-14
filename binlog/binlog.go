package binlog

import "fmt"

func (c *Conn) startBinLogStream() error {
	bldc := &BinLogDumpCommand{
		Status:   COMMAND_BIN_LOG_DUMP,
		Position: 120,
		Flags:    BINLOG_DUMP_NON_BLOCK,
		ServerId: c.Config.ServerId,
		Filename: c.Config.BinLogFile,
	}

	return c.writeBinLogDumpCommand(bldc)
}

func (c *Conn) listenForBinlog() error {
	res, err := c.listen()
	if err != nil {
		return err
	}

	fmt.Printf("res = %+v\n", res)

	// err = c.listenForBinlog()
	// if err != nil {
	// 	return err
	// }

	return nil
}
