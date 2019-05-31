package binlog

const BINLOG_DUMP_NON_BLOCK = 0x01
const COMMAND_BIN_LOG_DUMP = 0x12
const COMMAND_REGISTER_SLAVE = 0x15

type BinlogRegisterSlaveCommand struct {
	Status   uint64
	ServerId uint64
	Hostname string // Length Encoded
	User     string // Length Encoded
	Password string // Length Encoded
	Port     uint64
	ReplRank uint64
	MasterId uint64
}

func (c *Conn) writeBinlogRegisterSlaveCommand(brsc *BinlogRegisterSlaveCommand) error {
	c.putInt(TypeFixedInt, brsc.Status, 1)
	c.putInt(TypeFixedInt, brsc.ServerId, 4)
	c.putString(TypeLenEncString, brsc.Hostname)
	c.putString(TypeLenEncString, brsc.User)
	c.putString(TypeLenEncString, brsc.Password)
	c.putInt(TypeLenEncInt, brsc.Port, 2)
	c.putInt(TypeLenEncInt, brsc.ReplRank, 4)
	c.putInt(TypeLenEncInt, brsc.MasterId, 4)

	if c.Flush() != nil {
		return c.Flush()
	}

	return nil
}

type BinlogDumpCommand struct {
	Status   uint64
	Position uint64
	Flags    uint64
	ServerId uint64
	Filename string
}

func (c *Conn) writeBinlogDumpCommand(bldc *BinlogDumpCommand) error {
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
