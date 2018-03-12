package stp.libs;

import java.util.logging.Formatter;
import java.util.logging.LogRecord;

/**
 * Custom log formatter to enhance readability.
 */
public class LogFormatter extends Formatter {
	@Override
	public String format(LogRecord record) {
		return record.getLoggerName()+": "+formatMessage(record)+"\n";
	}
}
