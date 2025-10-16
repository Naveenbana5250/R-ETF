import java.io.*;
import java.util.Properties;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

public class AgentManager {
    public static void main(String[] args) throws IOException, InterruptedException {
        System.out.println("INFO: Java Agent Manager starting...");

        Properties props = new Properties();
        String configFilePath = "java_manager/agent.properties";
        try (FileInputStream fis = new FileInputStream(configFilePath)) {
            props.load(fis);
            System.out.println("INFO: Configuration loaded from " + configFilePath);
        } catch (IOException e) {
            System.err.println("FATAL: Could not load configuration file: " + configFilePath);
            e.printStackTrace();
            return;
        }

        String collectorPath = props.getProperty("collector.path");
        String orchestratorPath = props.getProperty("orchestrator.path");

        if (collectorPath == null || orchestratorPath == null) {
            System.err.println("FATAL: 'collector.path' or 'orchestrator.path' not found in config file.");
            return;
        }

        ProcessBuilder collectorBuilder = new ProcessBuilder("sudo", collectorPath);
        Process collectorProcess = collectorBuilder.start();
        System.out.println("INFO: Rust collector process started.");

        ProcessBuilder orchestratorBuilder = new ProcessBuilder("python3", orchestratorPath);
        Process orchestratorProcess = orchestratorBuilder.start();
        System.out.println("INFO: Python orchestrator process started.");

        Thread pipeThread = new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(collectorProcess.getInputStream()));
                 BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(orchestratorProcess.getOutputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    writer.write(line);
                    writer.newLine();
                    writer.flush();
                }
            } catch (IOException e) {
            }
        });
        pipeThread.start();
        System.out.println("INFO: Telemetry pipe is now active.");

        StreamGobbler alertGobbler = new StreamGobbler(orchestratorProcess.getInputStream(), System.out::println);
        Executors.newSingleThreadExecutor().submit(alertGobbler);

        StreamGobbler errorGobbler = new StreamGobbler(orchestratorProcess.getErrorStream(), System.err::println);
        Executors.newSingleThreadExecutor().submit(errorGobbler);

        int exitCode = collectorProcess.waitFor();
        System.out.println("INFO: Rust collector exited with code: " + exitCode);
    }
}

class StreamGobbler implements Runnable {
    private InputStream inputStream;
    private Consumer<String> consumer;

    public StreamGobbler(InputStream inputStream, Consumer<String> consumer) {
        this.inputStream = inputStream;
        this.consumer = consumer;
    }

    @Override
    public void run() {
        new BufferedReader(new InputStreamReader(inputStream)).lines().forEach(consumer);
    }
}
