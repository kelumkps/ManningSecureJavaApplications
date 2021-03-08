package com.johnsonautoparts;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Locale;
import java.util.Objects;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.johnsonautoparts.exception.AppException;
import com.johnsonautoparts.logger.AppLogger;
import com.johnsonautoparts.servlet.SessionConstant;

/**
 * 
 * Project3 class which contains all the method for the milestones. The task
 * number represents the steps within a milestone.
 * 
 * Each method has a name which denotes the type of security check we will be
 * fixing. There are several fields in the notes of each method:
 * 
 * TITLE - this is a description of code we are trying to fix RISK - Some
 * explanation of the security risk we are trying to avoid ADDITIONAL - Further
 * help or explanation about work to try REF - An ID to an external reference
 * which is used in the help of the liveProject
 * 
 */
public class Project3 extends Project {

	public Project3(Connection connection, HttpServletRequest httpRequest,
			HttpServletResponse httpResponse) {
		super(connection, httpRequest, httpResponse);
	}

	/**
	 * Project 3, Milestone 1, Task 1
	 * 
	 * TITLE: Suppressing exceptions
	 * 
	 * RISK: Developers sometimes catch exceptions and only print the stack or
	 * simply ignore. A program can become unstable if execution is allowed to
	 * pass an unexpected state. Malicious users could also leverage the logic
	 * error to bypass controls.
	 * 
	 * REF: CMU Software Engineering Institute ERR00-J
	 * 
	 * @param str
	 * @return String
	 */
	public boolean suppressException(String str) throws AppException {
		// try to authenticate the user
		try {
			httpRequest.authenticate(httpResponse);
		} catch (IOException ioe) {
			ioe.printStackTrace();
			AppLogger.log("login IO error: " + ioe.getMessage());
			throw new AppException("login exception: " + ioe.getMessage());
		} catch (ServletException se) {
			AppLogger.log("Servlet Exception: " + se.getMessage());
			throw new AppException("login exception: " + se.getMessage());
		}

		// reached this far so return true
		return true;
	}

	/**
	 * Project 3, Milestone 1, Task 2
	 * 
	 * TITLE: Sensitive data exposure from exceptions
	 * 
	 * RISK: Returning sensitive data to a user can allow for malicious
	 * discovery of files on the file system. With direct feedback, a malicious
	 * user could continue to try different combinations to find sensitive data.
	 * 
	 * REF: CMU Software Engineering Institute ERR01-J
	 * 
	 * @param filePath
	 * @return String contents of the file or information about the error
	 */
	public String dataExposure(String filePath) throws AppException {
		try {
			Path path = Paths.get(filePath);

			StringBuilder sb = new StringBuilder();

			// read the data stream of the file into string
			try (Stream<String> stream = Files.lines(path)) {
				stream.forEach(s -> sb.append(s).append("\n"));

				return sb.toString();
			} catch (IOException ex) {
				AppLogger.log("Error reading file: " + ex.getMessage());
				throw new AppException("Error reading file: " + ex.getMessage());
			}
		} catch (InvalidPathException ipe) {
			AppLogger.log("Error with requested file: " + ipe.getMessage());
			throw new AppException("Error with requested file: " + ipe.getMessage());
		}

	}

	/**
	 * Project 3, Milestone 1, Task 3
	 * 
	 * TITLE: Exceptions during logging
	 * 
	 * RISK: Logging information to uncontrolled streams cannot guarantee that
	 * the audit data is successfully captured. Malicious activity could be
	 * concealed or lost if it is not logged in a guaranteed manner.
	 * 
	 * REF: CMU Software Engineering Institute ERR02-J
	 * 
	 * @param userData
	 * @return String
	 */
	public String exceptionLogging(String userData) throws AppException {
		// get session data
		try {
			HttpSession session = httpRequest.getSession();
			Object userDataObj = session.getAttribute(userData);

			// check if userData was retrieved
			if (userDataObj == null) {
				throw new IllegalStateException("userData is null");
			}

			// return the data
			if (userDataObj instanceof String) {
				return (String) userDataObj;
			} else {
				throw new IllegalStateException("no user data in session");
			}
		} catch (IllegalStateException se) {
			throw new AppException(
					"getSession() caused IllegalState: " + se.getMessage());
		}
	}

	/**
	 * Project 3, Milestone 2, Task 1
	 * 
	 * TITLE: Restore object state on failure
	 * 
	 * RISK: Upon failure, the state of a object should be returned to the
	 * previous state or the data can become out of sync. Malicious users can
	 * leverage the logic error to bypass controls or perform a denial of
	 * service.
	 * 
	 * ADDITONAL: The method retrieves the contents of a PDF file in the
	 * database accessed by the ID passed to the method. The method keeps track
	 * of the number of documents accessed during the existing session. This is
	 * done by retrieving the value of the session attribute "docs_accessed".
	 * Each time a document is accessed, the value of "docs_accessed" is
	 * incremented.
	 * 
	 * REF: CMU Software Engineering Institute ERR03-J
	 * 
	 * @param pdfId
	 * @return String
	 */
	public String restoreState(String pdfId) throws AppException {
		HttpSession session = httpRequest.getSession();
		Object accessedObj = session
				.getAttribute(SessionConstant.DOCS_ACCESSED);

		// track number of docs accessed in session
		int accessed = 0;

		// update if it existing or leave as zero
		if (accessedObj instanceof Integer) {
			accessed = (Integer) accessedObj;
		}

		// get the content from the database
		try {
			String sql = "SELECT content FROM docs WHERE id = ?";
			try (PreparedStatement stmt = connection.prepareStatement(sql)) {

				// force the id into an integer by casting and catching any
				// exceptions
				int id = 0;
				try {
					id = Integer.parseInt(pdfId);
				} catch (NumberFormatException nfe) {
					throw new AppException(
							"restoreState failed to parse integer: "
									+ nfe.getMessage());
				}

				// set the parameter and execute the SQL
				stmt.setInt(1, id);
				try (ResultSet rs = stmt.executeQuery()) {

					// return the count
					if (rs.next()) {
						String result = rs.getString(1);
						if (Objects.nonNull(result)) {
							// increment the docs_accessed in the session attribute
							session.setAttribute(SessionConstant.DOCS_ACCESSED, accessed + 1);
							return result;
						} else {
							throw new AppException("restoreState return null result");
						}
					} else {
						throw new AppException(
								"restoreState did not return any results");
					}
				} // end resultset
			} // end statement

		} catch (SQLException se) {
			throw new AppException(
					"restoreState caught SQLException: " + se.getMessage());
		} finally {
			try {
				connection.close();
			} catch (SQLException se) {
				// this is an application error but does not represent an error
				// for the user
				AppLogger.log("restoreState failed to close connection: "
						+ se.getMessage());
			}
		}

	}

	/**
	 * Project 3, Milestone 2, Task 2
	 * 
	 * TITLE: Exception handling flow
	 * 
	 * RISK: The finally clause should be used to clean up after an exception is
	 * caught but should not end execution flow abruptly. The finally block
	 * should also not execute any methods which could cause new exceptions to
	 * be thrown.
	 * 
	 * REF: CMU Software Engineering Institute ERR004-J, ERR05-J
	 * 
	 * @param fileContents
	 * @return String
	 */
	public boolean flowHandling(String fileContents) throws Exception {
		File f = null;
		BufferedWriter writer = null;

		// write the contents to a temporary file
		try {
			f = File.createTempFile("temp", null);
			writer = new BufferedWriter(new FileWriter(f.getCanonicalPath()));
		} catch (IOException ioe) {
			throw new AppException(
					"flowHandling caught IO exception: " + ioe.getMessage());
		} finally {
			if (writer != null) {
				try {
					writer.close();
				} catch (IOException e) {
					AppLogger.log("flowHandling failed to close writer: "
							+ e.getMessage());
				}
			}
		}
		return true;
	}

	/**
	 * Project 3, Milestone 2, Task 3
	 * 
	 * TITLE: Throwing or catching RuntimeException
	 * 
	 * RISK: Runtime exception should not be thrown or caught since it
	 * represents a major programmatic error. The generic Exception should not
	 * be caught or thrown either since the reason for the error cannot be
	 * distinguished.
	 * 
	 * REF: CMU Software Engineering Institute ERR07-J
	 * 
	 * @param cmd
	 * @return String
	 */
	public String runtimeException(String cmd) throws AppException {
		try {
			// execute the OS command
			if (!Pattern.matches("[0-9A-Za-z]+", cmd)) {
				throw new AppException("exec was passed a cmd with illegal characters");
			}

			// execute the requested command
			Runtime rt = Runtime.getRuntime();
			Process proc = rt.exec(new String[]{"sh", "-c", cmd + " "});
			int result = proc.waitFor();

			if (result != 0) {
				throw new AppException("process error: " + result);
			}
			InputStream in = proc.getInputStream();

			// return the results of executing the command
			StringBuilder strBuilder = new StringBuilder();
			int i;

			while ((i = in.read()) != -1) {
				strBuilder.append((char) i);
			}

			return strBuilder.toString();
		} catch (IOException ioe) {
			throw new AppException("exec caught IO error: " + ioe.getMessage());
		} catch (InterruptedException ie) {
			throw new AppException(
					"exec caught interupted error: " + ie.getMessage());
		}
	}

	/**
	 * Project 3, Milestone 1, Task 4
	 * 
	 * TITLE: Handling NullPointerException
	 * 
	 * RISK: Accessing a null object represents a major programmatic error and
	 * can cause the application to crash which results in a denial of service.
	 * Developers should not catch NullPointerException; instead, objects which
	 * may be null should always be checked.
	 * 
	 * REF: CMU Software Engineering Institute ERR08-J
	 * 
	 * @param str
	 * @return String
	 */
	public boolean testNull(String str) throws AppException {
		if (Objects.nonNull(str)) {
			// check if str is empty
			return str.isEmpty();
		} else {
			throw new AppException("testNull received null object");
		}
	}

	/**
	 * Project 3, Milestone 3, Task 1
	 * 
	 * TITLE: Ignoring return values
	 * 
	 * RISK: Values returned by methods should not be ignored. The methods which
	 * return values include String replacing or actions such as deleting a
	 * file. The return value should be evaluated and errors handled even if
	 * they do not throw an exception.
	 * 
	 * REF: CMU Software Engineering Institute EXP00-J
	 * 
	 * @param fileName
	 * @return String
	 */
	public String deleteFile(String fileName) throws AppException {
		if (fileName == null) {
			throw new AppException("deleteFile passed a null variable");
		}

		fileName = fileName.replaceAll("\\.", "_");
		File f = new File(fileName);

		// delete the file
		try {
			boolean delete = f.delete();
			if (delete) {
				return ("Deleted file: " + f.getCanonicalPath());
			} else {
				throw new AppException("Unable to delete file: " + f.getCanonicalPath());
			}
		} catch (IOException ioe) {
			throw new AppException(
					"deleteFile caught IO exception: " + ioe.getMessage());
		}
	}

	/**
	 * Project 3, Milestone 3, Task 2
	 * 
	 * TITLE: Avoiding null objects
	 * 
	 * RISK: Calling methods on null objects results in unstable application
	 * flow and will crash programs. Object passed to methods or created should
	 * always be tested for null if there is a chance the object does not result
	 * in a default value.
	 * 
	 * REF: CMU Software Engineering Institute EXP01-J and EXP54-J
	 * 
	 * @param str
	 * @return String
	 */
	public String manipulateString(String str) throws AppException {
		// check if the value is null or empty before manipulating string
		if (str == null || str.isEmpty()) {
			throw new AppException("manipulate string sent null or empty");
		}

		String manipulated = str.toUpperCase(Locale.ENGLISH);
		return manipulated.replaceAll("\\.", "_");
	}

	/**
	 * Project 3, Milestone 3, Task 3
	 * 
	 * TITLE: Detect file-related errors
	 * 
	 * RISK: Some file handling methods report errors which are not thrown as
	 * exceptions. Developers should understand these errors and account for
	 * them. The error could cause under read/write of data or overflows which
	 * could result in an unstable application, crashes, or other events which
	 * then cause security issues.
	 * 
	 * REF: CMU Software Engineering Institute FIO02-J
	 * 
	 * @param fileName
	 * @return String
	 */
	public String detectFileError(String fileName) throws AppException {
		if (fileName == null || fileName.isEmpty()) {
			throw new AppException("fileName is null or empty");
		}
		final int BUFFER = 1024;

		byte[] data = new byte[BUFFER];

		// read the first 1024 bytes of the file
		try (FileInputStream fis = new FileInputStream(fileName)) {
			int read = fis.read(data, 0, BUFFER);
			if (read == 0) {
				throw new AppException("reads zero bytes");
			}

			// return the data from file read as a string
			// for this exercise, you can ignore checking if the data read is a
			// valid
			// string or characters. we are only interested in file-related
			// errors
			return Arrays.toString(data);
		} catch (FileNotFoundException fnfe) {
			throw new AppException("detectFileError could not find file: "
					+ fnfe.getMessage());
		} catch (IOException ioe) {
			throw new AppException(
					"detectFileError caught IO exception: " + ioe.getMessage());
		}
	}

	/**
	 * Project 3, Milestone 3, Task 4
	 * 
	 * TITLE: Recover from an unstable state
	 * 
	 * RISK: Long running threads or other types of loop that may get stuck in a
	 * lock or continue to consume resources and not exit gracefully. In the
	 * worst case, the unstable state may cause the entire application to crash.
	 * In these specific cases, it is acceptable to catch the generic Throwable
	 * which includes RuntimeException.
	 * 
	 * ADDITIONAL: The method to review is the recoverState(). The CheckSession
	 * runnable class is only a helper. Focus on how to make the recoverState()
	 * able to exit gracefully if the possible infinite loop in the Thread
	 * continues waiting for the session variable which never appears.
	 * 
	 * REF: CMU Software Engineering Institute ERR53-J Additional information on
	 * pro/con of catching Throwable:
	 * https://www.baeldung.com/java-catch-throwable-bad-practice
	 * 
	 * @param str
	 * @return String
	 */
	public void recoverState(String str) throws AppException {
		// create the thread to look for the data_id attribute in the session so
		// we can
		// do further processing
		Runnable checkSessionRunnable = new CheckSession(
				httpRequest.getSession());

		try {
			Thread t = new Thread(checkSessionRunnable);
			t.start();
		} catch (Throwable throwable) {
			AppLogger.log("Error while check session : " + throwable.getMessage());
			throw new AppException("Error while check session");
		}
	}

	/**
	 * This class is part of Project 3, Milestone3, Task 4 NO CHANGES NEED TO BE
	 * PERFORMED ON THIS CLASS
	 */
	public static class CheckSession implements Runnable {
		private HttpSession session = null;
		boolean found = false;
		int waitTime = 5000;

		public CheckSession(HttpSession session) {
			this.session = session;
		}

		@Override
		public void run() {
			Object dataId = null;

			try {
				// loop until we see the data_id attribute in the session
				while (!found) {
					dataId = session.getAttribute("data_id");

					if (dataId instanceof String) {
						found = true;
					} else {
						Thread.sleep(waitTime);
					}
				}
			} catch (InterruptedException ie) {
				AppLogger.log("thread was interrupted: " + ie.getMessage());
				Thread.currentThread().interrupt();
			} catch (IllegalArgumentException iae) {
				AppLogger.log("thread caught illegal argumen to sleep: "
						+ iae.getMessage());
			}

		}
	}

	/**
	 * Project 3, Milestone 3, Task 5
	 * 
	 * TITLE: Handle open resources in cascading try-catch-finally
	 * 
	 * RISK: Multiple resources used with a finally block may not execute if one
	 * of the previous methods fail. For example, if multiple Streams are opened
	 * within a try block and the finally performs a close() one after the
	 * other, if any of the close() throws an exception, the flow will exit and
	 * the finally close() statements with not execute. The failure to close
	 * resources could leave an application in an unstable state.
	 * 
	 * REF: CMU Software Engineering Institute ERR54-J
	 * 
	 * @param zipFile
	 * @return String
	 */
	public boolean handleClose(String zipFile)
			throws AppException, IOException {
		FileInputStream fis = null;
		ZipInputStream zis = null;
		FileOutputStream fos = null;
		BufferedOutputStream dest = null;

		final int BUFFER = 512;
		int count = 0;

		// create a path to the zipFile
		Path zipPath = null;
		try {
			zipPath = Paths.get("temp", "zip", "zipFile");
		} catch (InvalidPathException ipe) {
			throw new AppException(
					"handleClose received an invalid zipFile path: "
							+ ipe.getMessage());
		}

		byte[] data = null;

		try {
			// open the zip file
			fis = new FileInputStream(zipFile.toString());
			zis = new ZipInputStream(new BufferedInputStream(fis));
			ZipEntry entry;

			/**
			 * write the zip files
			 *
			 * the code is simplified to reduce the size and does not take into
			 * account lessons learned in other projects about avoiding zip
			 * bombs you do not need to fix that issue here
			 */
			while ((entry = zis.getNextEntry()) != null) {
				try {
					fos = new FileOutputStream(zipPath + entry.getName());
					dest = new BufferedOutputStream(fos);

					while ((count = zis.read(data, 0, BUFFER)) != -1) {
						dest.write(data, 0, count);
					}

					// clean up the zip entry
					dest.flush();
					zis.closeEntry();
				}
				// clean up and close the resources
				finally {
					if (fos != null) {
						try {
							fos.close();
						} catch (IOException e) {
							AppLogger.log("Error while closing fos : " + e.getMessage());
						}
					}
					if (dest != null) {
						try {
							dest.close();
						} catch (IOException e) {
							AppLogger.log("Error while closing dest : " + e.getMessage());
						}
					}
				}
			}

			// zip extracted correctly with no errors
			return true;

		} catch (FileNotFoundException fnfe) {
			throw new AppException("zip file not found: " + fnfe.getMessage());
		}
		// clean up the resources used to open the zip file
		finally {
			if (fis != null) {
				try {
					fis.close();
				} catch (IOException e) {
					AppLogger.log("Error while closing fix : " + e.getMessage());
				}
			}
			if (zis != null) {
				try {
					zis.close();
				} catch (IOException e) {
					AppLogger.log("Error while closing zis : " + e.getMessage());
				}
			}
		}

	}
}
