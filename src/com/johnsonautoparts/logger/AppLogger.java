package com.johnsonautoparts.logger;

import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * NO CHANGES NEEDED ON THIS CLASS FOR THE liveProject
 * 
 * Some milestones may suggest extra work for bonus credit by updating this
 * class.
 * 
 * The AppLogger provides a common log() method for logging through out the
 * application A real application may provide more robust logging, but for this
 * exercise, the logging will be sent to the webapp logs if built and deployed
 * into Tomcat.
 * 
 */

public class AppLogger {
	private static final Logger logger = Logger.getLogger("JohnsonAutoParts");

	public static void log(String message) {
		logger.info(sanitize(message));
	}

	private static String sanitize(String msg) {
		Pattern newline = Pattern.compile("\n");
		Matcher matcher = newline.matcher(msg);
		return matcher.replaceAll("\n  ");
	}
}
