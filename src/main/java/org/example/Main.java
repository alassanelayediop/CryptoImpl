package org.example;

public class Main
{
    public static void main(String[] args)
    {
        App.main(args);
    }
}

// jpackage --type exe --input . --dest . --main-jar demo.jar --main-class com.example.demo.App --module-path "C:\Program Files\Java\javafx-jmods-23.0.1" --add-modules javafx.controls,javafx.fxml --win-shortcut
