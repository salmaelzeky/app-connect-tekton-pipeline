package esb.framework.java.lib;

public class ConsoleLog {

	public static void log(String desc , String guid , String data) {
		System.out.println("Desc: "+desc+" , GUID: " + guid +" , MSG: "+ data);
	}
}
