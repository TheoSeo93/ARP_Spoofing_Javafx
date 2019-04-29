package controller;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.layout.AnchorPane;
import javafx.stage.Stage;

public class Main extends Application{
	public static Pcap pcap = null;
	public static PcapIf device =null;
	
	private Stage primaryStage;
	private AnchorPane layout;
	
	/*
	 * Hacker: "I will make sender send IP to me instead of router(target)"
	 */
	public static byte[] myIP = null;
	//Victim IP
	public static byte[] senderIP = null;
	//Router IP
	public static byte[] targetIP = null;
	

	public static byte[] senderMAC = null;
	public static byte[] myMAC = null;
	public static byte[] targetMAC = null;
	
	@Override
	public void start(Stage primaryStage) {
		this.primaryStage =primaryStage;
		this.primaryStage.setTitle("ARP Spoofing");
		this.primaryStage.setOnCloseRequest(e->System.exit(0));
		setLayout();
	}
	
	public void setLayout() {
		try {
			FXMLLoader loader = new FXMLLoader();
			loader.setLocation(Main.class.getResource("../view/view.fxml"));
			layout = (AnchorPane)loader.load();
			Scene scene = new Scene(layout);
			primaryStage.setScene(scene);
			primaryStage.show();
		}catch (Exception e) {
			e.printStackTrace();
		}
	}
	public Stage getPrimaryStage() {
		return primaryStage;
	}
	public static void main(String[] args) {
		launch(args);
	}
}
