package io.github.tracer021.maven.resign;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.util.Formatter;

public class Entitlement {

	private final String applicationIdentifier;
	private final String teamIdentifier;
	private final String keychainAccessGroups;
	private final File path;
	
	public Entitlement(String applicationIdentifier, String teamIdentifier, String keychainAccessGroups, File path) {
		this.applicationIdentifier = applicationIdentifier;
		this.teamIdentifier = teamIdentifier;
		this.keychainAccessGroups = keychainAccessGroups;
		this.path = path;
	}
	
	public File createEntitlementFile() throws Exception {
		String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?> " +
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">"+
"<plist version=\"1.0\">"+
"<dict>"+
"        <key>application-identifier</key>"+
"        <string>%s</string>"+
"        <key>com.apple.developer.team-identifier</key>"+
"        <string>%s</string>"+
"        <key>get-task-allow</key>"+
"        <false/>"+
"        <key>keychain-access-groups</key>"+
"        <array>"+
"                <string>%s</string>"+
"        </array>"+
"</dict>"+
"</plist>";
		
		Formatter formatter = new Formatter().format(xml, new Object[]{applicationIdentifier, teamIdentifier, keychainAccessGroups});
		String formattedString = formatter.toString();
		formatter.close();
		File file = new File(path.getAbsolutePath()+"/entitlement.plist");

		try(BufferedWriter writer = new BufferedWriter(new FileWriter(file)) ) {
			writer.write(formattedString);
		} catch(Exception e) {
			throw e;
		}
		return file;
	}
}
