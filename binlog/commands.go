package binlog

const COMMAND_BIN_LOG_DUMP = 0x12
const BINLOG_DUMP_NON_BLOCK = 0x01

type BinLogDumpCommand struct {
	Status   uint64
	Position uint64
	Flags    uint64
	ServerId uint64
	Filename string
}

func (c *Conn) writeBinLogDumpCommand(bldc *BinLogDumpCommand) error {
	c.putInt(TypeFixedInt, bldc.Status, 1)
	c.putInt(TypeFixedInt, bldc.Position, 4)
	c.putInt(TypeFixedInt, bldc.Flags, 2)
	c.putInt(TypeFixedInt, bldc.ServerId, 4)
	c.putString(TypeRestOfPacketString, bldc.Filename)

	if c.Flush() != nil {
		return c.Flush()
	}

	return nil
}
