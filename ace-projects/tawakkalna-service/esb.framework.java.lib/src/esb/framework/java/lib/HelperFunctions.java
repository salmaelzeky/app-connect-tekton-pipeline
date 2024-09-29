package esb.framework.java.lib;

public class HelperFunctions {
	
	public static Boolean matchRegex(String text, String regexPattern) {
		try {
			return text.matches(regexPattern);
		} catch (Exception e) {
			return false;
		}
	}

}
