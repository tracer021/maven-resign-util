package io.github.tracer021.maven.resign;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;
import org.codehaus.plexus.util.StringUtils;
import org.codehaus.plexus.util.cli.CommandLineException;
import org.codehaus.plexus.util.cli.CommandLineUtils;
import org.codehaus.plexus.util.cli.Commandline;

import edu.emory.mathcs.backport.java.util.Arrays;
import net.lingala.zip4j.core.ZipFile;
import net.lingala.zip4j.exception.ZipException;
import net.lingala.zip4j.model.ZipParameters;

@Mojo(name="resign", defaultPhase=LifecyclePhase.PACKAGE)
public class ResignUtilMojo extends AbstractMojo {

	@Parameter(property="resign.ipaPath")
	private String ipaPath;

	@Parameter(property="resign.mobileProvisionPath")
	private String mobileProvisionPath;

	@Parameter(property="resign.certId")
	private String certId;

	@Parameter(property="resign.scriptPathToUnlockKeychain")
	private String scriptPathToUnlockKeychain;

	@Parameter(property="resign.keyChainPath")
	private String keyChainPath;

	@Parameter(property="resign.keyChainPassword")
	private String keyChainPassword;
	
	@Parameter(property="resign.showCerttool")
	private boolean showCerttool;
	
	@Parameter(property="resign.keyChainFileName")
	private String keyChainFileName;
	
	@Parameter(property="resign.identifier", required=true)
	private String identifier;

	private static final String BUILD_DIR = "resign-util";

	private File appPath;

	private final String PATTERN_APP_ID = "<key>application-identifier</key>\\s*<string>([\\w\\.]+)</string>";
	private final String PATTERN_TEAM_ID = "<key>TeamIdentifier</key>\\s*<array>\\s*<string>(\\w+)";
	private final String PATTERN_KCAG = "<key>keychain-access-groups</key>\\s*<array>\\s*<string>([\\w\\.\\*]+)</string>\\s*</array>";
	private final String PATTERN_TEAM_NAME = "<key>TeamName</key>\\s*<string>(.+)</string>\\s*<key>TimeToLive</key>";

	@Component
	private MavenProject mavenProject;

	public void execute() throws MojoExecutionException, MojoFailureException {
		try {
			File originalIPA = extractOldIPA();
			File payloadFile = getFile("Payload/");
			String appName = payloadFile.list()[0];
			deleteCodeSignatureFile(payloadFile, appName);

			File oldMobileProvision = new File(appPath.getAbsoluteFile() + "/embedded.mobileprovision");
			Files.copy(new File(mobileProvisionPath).toPath(), oldMobileProvision.toPath(), StandardCopyOption.REPLACE_EXISTING);
			String text = extractPrintableString(oldMobileProvision);
			File entitlementFile = createEntitlementsFile(text);
			String certName = getCertificateName(text);

			Commandline commandLine = new Commandline();
			showCerts(commandLine);
			unlockKeyChain(commandLine);
			codeSign(commandLine, certName, entitlementFile);

			zipResigned(originalIPA, payloadFile);
			getLog().info("Done. Resigned ipa: "  + originalIPA.getAbsolutePath());

		} catch(Exception e) {
			throw new MojoExecutionException("Failed",e);
		}
	}

	private void showCerts(Commandline commandLine) throws CommandLineException {
		if (showCerttool) {
			commandLine.clear();
			CommandLineUtils.StringStreamConsumer err = new CommandLineUtils.StringStreamConsumer();
			CommandLineUtils.StringStreamConsumer out = new CommandLineUtils.StringStreamConsumer();
			String[] args = new String[]{"y"};
			commandLine.setExecutable("/usr/bin/certtool");
			commandLine.addArguments(args);
			CommandLineUtils.executeCommandLine(commandLine, out, err);
			logCommandOuputs(err, out);
		}
	}

	private void zipResigned(File originalIPA, File payloadFile) throws IOException, ZipException {
		File renameOldIPA = new File(originalIPA.getAbsolutePath() + ".old");
		Files.move(originalIPA.toPath(), renameOldIPA.toPath(), StandardCopyOption.REPLACE_EXISTING);
		ZipFile zipFile = new ZipFile(originalIPA);
		zipFile.addFolder(payloadFile, new ZipParameters());
	}

	private void logCommandOuputs(CommandLineUtils.StringStreamConsumer err , CommandLineUtils.StringStreamConsumer out) {
		String output = out.getOutput();
		Log logger = getLog();
		if (!StringUtils.isEmpty(output)) {
			logger.info(output);
		}

		String error = err.getOutput();
		if (!StringUtils.isEmpty(error)) {
			logger.error(error);
		}
	}

	private void unlockKeyChain(Commandline commandLine) throws Exception {
		commandLine.clear();
		Log logger = getLog();
		CommandLineUtils.StringStreamConsumer err = new CommandLineUtils.StringStreamConsumer();
		CommandLineUtils.StringStreamConsumer out = new CommandLineUtils.StringStreamConsumer();
		int exitCode;
		if (scriptPathToUnlockKeychain != null) {
			commandLine.setExecutable(scriptPathToUnlockKeychain);
			exitCode = CommandLineUtils.executeCommandLine(commandLine, out, err);


		} else if (keyChainPath != null && keyChainPassword != null) {
			String []args = new String[]{"unlock-keychain", "-p", keyChainPassword , keyChainPath};
			commandLine.setExecutable("/usr/bin/security");
			commandLine.clearArgs();
			commandLine.addArguments(args);
			exitCode = CommandLineUtils.executeCommandLine(commandLine, out, err);

		} else {
			logger.info("No script path or keychain password and path combination supplied");
			logger.info("Will not unlock keychain");
			return;
		}
		logger.debug(commandLine.toString());
		logger.info("Unlock KeyChain Exit Code: " + exitCode);
		logCommandOuputs(err, out);
	}

	private void codeSign(Commandline commandLine, String certName, File entitlementFile) throws Exception {
		commandLine.clear();
		String[] args = new String[]{"-f", "-s", quoteString(certName), "--entitlements", quoteString(entitlementFile.getAbsolutePath()), 
				quoteString(appPath.getAbsolutePath()), "--identifier", identifier };
		List<String> list = new ArrayList<>(Arrays.asList(args));
		if (keyChainFileName != null) {
			list.add("--keychain");
			list.add(keyChainFileName);
		}
		String command = "/usr/bin/codesign";
		commandLine.setExecutable(command);
		commandLine.addArguments(list.toArray(new String[]{}));
		CommandLineUtils.StringStreamConsumer err = new CommandLineUtils.StringStreamConsumer();
		CommandLineUtils.StringStreamConsumer out = new CommandLineUtils.StringStreamConsumer();
		int exitCode = CommandLineUtils.executeCommandLine(commandLine, out, err);
		getLog().debug(commandLine.toString());
		getLog().info("Code Sign Exit Code: " + exitCode);
		logCommandOuputs(err, out);	
		if (exitCode != 0) {
			throw new Exception("Code sign failed");
		}

	}


	private File createEntitlementsFile(String text) throws Exception {
		String applicationIdentifier, teamIdentifier, keyChainAccessGroup;
		applicationIdentifier = find(text, PATTERN_APP_ID, "applicationIdentifier");
		teamIdentifier = find(text, PATTERN_TEAM_ID, "teamIdentifier");
		keyChainAccessGroup = find(text, PATTERN_KCAG, "key-chain-access-group");

		Entitlement entitlement = new Entitlement(applicationIdentifier, teamIdentifier, keyChainAccessGroup, getFile());
		File entitlementFile = entitlement.createEntitlementFile();
		return entitlementFile;
	}

	private String getCertificateName(String text) throws Exception {
		if (certId != null) {
			return certId;
		} 
		String teamName = find(text, PATTERN_TEAM_NAME, "teamName");
		return "iPhone Distribution: " + teamName;
	}

	private String extractPrintableString(File oldMobileProvision) throws Exception {
		StringBuilder sb = new StringBuilder();
		try (BufferedReader reader = new BufferedReader(new FileReader(oldMobileProvision))) {
			int i = 0;
			while((i = reader.read()) != -1 ) {
				if (32 <= i && i <= 127) {
					sb.append((char)i);	
				}
			}
		} catch(Exception e) {
			throw e;
		}
		return sb.toString();
	}

	private String find(String sb, String stringPattern, String errorKey) throws Exception {
		Pattern pattern = Pattern.compile(stringPattern);
		Matcher matcher = pattern.matcher(sb.toString());
		String result;
		if (matcher.find()) {
			result = matcher.group(1);
		} else {
			throw new Exception("Unable to find " + errorKey);
		}
		return result;
	}

	private void deleteCodeSignatureFile(File payloadFile, String appName) {
		appPath = new File(payloadFile.getAbsolutePath()+"/"+appName);
		File file = new File(appPath.getAbsolutePath() + "/_CodeSignature");
		if (file.list() != null ) {
			for(String f : file.list()) {
				new File(file.getPath() +"/" + f).delete();
			}
			file.delete();
		}
	}

	private File extractOldIPA() throws IOException, ZipException {
		File sourceIPA = new File(ipaPath);
		getFile().mkdirs();
		File oldIPADest = new File(getFile().getPath() +"/" +sourceIPA.getName());
		Files.copy(sourceIPA.toPath(), oldIPADest.toPath(), StandardCopyOption.REPLACE_EXISTING);
		ZipFile zipFile = new ZipFile(oldIPADest);
		zipFile.extractAll(getFile().getAbsolutePath());
		return oldIPADest;
	}

	private File getFile(String path) {
		String additionalPath = path != null ? path : "";
		return new File(mavenProject.getBuild().getDirectory() + "/"
				+BUILD_DIR + "/" + additionalPath);
	}

	private File getFile() {
		return getFile(null);
	}

	private String quoteString(String originalString) {
		StringBuilder sb = new StringBuilder("'");
		sb.append(originalString.replaceAll("\"", "\\\\\""));

		sb.append("'");
		return sb.toString();
	}

}
