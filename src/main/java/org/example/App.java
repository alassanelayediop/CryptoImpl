package org.example;

import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.scene.text.Font;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import org.example.crypto.*;
import org.example.crypto.aes.CryptoAES;
import org.example.crypto.dh.DiffieHellmanService;
import org.example.crypto.hash.HashService;
import org.example.crypto.rsa.CryptoRSA;

import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.Objects;

public class App extends Application {

    /* ===== LOGIQUE ===== */
    private Icrypto crypto;
    private DiffieHellmanService dhService;

    /* ===== UI PRINCIPALE ===== */
    private TabPane mainTabPane;
    private ComboBox<CryptoType> cbCryptoType;
    private ComboBox<KeySize> cbKeySize;
    private ComboBox<CryptoMode> cbCryptoMode;

    /* ===== CHIFFREMENT/DÉCHIFFREMENT ===== */
    private TextArea taInput;
    private TextArea taOutput;
    private TextArea taAESKey;
    private TextArea taRSAPublicKey;
    private TextArea taRSAPrivateKey;
    private RadioButton rbEncrypt;
    private RadioButton rbDecrypt;
    private Button btnProcess;
    private VBox rsaKeyManagement;

    /* ===== SIGNATURE RSA ===== */
    private TextArea taSignInput;
    private TextArea taSignOutput;
    private TextArea taSignature;
    private RadioButton rbSign;
    private RadioButton rbVerify;
    private Button btnSignProcess;

    /* ===== HACHAGE ===== */
    private ComboBox<HashAlgorithm> cbHashAlgorithm;
    private TextArea taHashInput;
    private TextArea taHashOutput;
    private TextArea taHashCompare;
    private Label lblHashInfo;

    /* ===== DIFFIE-HELLMAN ===== */
    private ComboBox<Integer> cbDHKeySize;
    private TextArea taDHPublicKey;
    private TextArea taDHOtherPublicKey;
    private TextArea taDHSharedSecret;
    private Label lblDHStatus;

    @Override
    public void start(Stage stage) {
        loadFontAwesome();
        crypto = new CryptoAES();
        dhService = new DiffieHellmanService();

        /* =========================
           TABPANE PRINCIPAL
        ========================= */
        mainTabPane = new TabPane();
        mainTabPane.setTabClosingPolicy(TabPane.TabClosingPolicy.UNAVAILABLE);

        Tab tabCrypto = new Tab("Chiffrement/Déchiffrement");
        tabCrypto.setContent(createCryptoTab(stage));

        Tab tabHash = new Tab("Hachage");
        tabHash.setContent(createHashTab(stage));

        Tab tabSignature = new Tab("Signature RSA");
        tabSignature.setContent(createSignatureTab(stage));

        Tab tabDH = new Tab("Diffie-Hellman");
        tabDH.setContent(createDiffieHellmanTab(stage));

        mainTabPane.getTabs().addAll(tabCrypto, tabHash, tabSignature, tabDH);


        /* =========================
           SCENE
        ========================= */
        VBox root = new VBox(mainTabPane);
        VBox.setVgrow(mainTabPane, Priority.ALWAYS);
        root.setPadding(new Insets(10));

        Scene scene = new Scene(root, 1200, 750);
        scene.getStylesheets().add(
                Objects.requireNonNull(getClass().getResource("/styles.css")).toExternalForm()
        );

        stage.setTitle("Cryptographie Complète - AES/RSA/Hash/DH");
        stage.setScene(scene);
        stage.show();
    }

    /* =========================
       ONGLET CHIFFREMENT/DÉCHIFFREMENT
    ========================= */
    private VBox createCryptoTab(Stage stage) {
        /* Configuration */
        cbCryptoType = new ComboBox<>();
        cbCryptoType.getItems().addAll(CryptoType.values());
        cbCryptoType.setValue(CryptoType.AES);

        cbKeySize = new ComboBox<>();
        updateKeySizes(CryptoType.AES);

        cbCryptoMode = new ComboBox<>();
        cbCryptoMode.getItems().addAll(CryptoMode.values());
        cbCryptoMode.setValue(CryptoMode.ECB);
        cbCryptoMode.setOnAction(e -> crypto.setMode(cbCryptoMode.getValue()));

        VBox configBox = new VBox(10,
                new Label("Algorithme"), cbCryptoType,
                new Label("Mode"), cbCryptoMode,
                new Label("Taille de clé"), cbKeySize
        );
        configBox.setStyle("-fx-background-color: rgba(0,0,0,0.3); -fx-padding: 15; -fx-background-radius: 8;");
        configBox.setMaxWidth(300);

        /* Clés */
        taAESKey = createStyledTextArea("Clé AES (Base64)", 2);
        taRSAPublicKey = createStyledTextArea("Clé publique RSA", 3);
        taRSAPrivateKey = createStyledTextArea("Clé privée RSA", 3);
        taAESKey.setEditable(false);
        taRSAPublicKey.setEditable(false);
        taRSAPrivateKey.setEditable(false);
        showAESKeys();

        Button btnGenKey = createIconButton("\uf084", " Générer");
        Button btnLoadKey = createIconButton("\uf07c", " Charger");
        Button btnSaveKey = createIconButton("\uf0c7", " Sauvegarder");

        btnGenKey.setOnAction(e -> {
            try {
                crypto.genKey(cbKeySize.getValue().getSize());
                refreshKeyDisplay();
                info("Succès", "Clé générée");
            } catch (Exception ex) {
                handleError(ex, "génération de clé");
            }
        });

        btnLoadKey.setOnAction(e -> {
            try {
                File f = chooseFileOpen(stage, "Charger une clé");
                if (f != null) {
                    crypto.loadKey(f);
                    refreshKeyDisplay();
                    info("Succès", "Clé chargée");
                }
            } catch (Exception ex) {
                handleError(ex, "chargement de clé");
            }
        });

        btnSaveKey.setOnAction(e -> {
            try {
                String name = String.format("%s_Key_%s_%dbits",
                        cbCryptoType.getValue(), cbCryptoMode.getValue(),
                        cbKeySize.getValue().getSize());
                File f = chooseFileSave(stage, "Sauvegarder la clé", name);
                if (f != null) {
                    crypto.saveKey(f);
                    info("Succès", "Clé sauvegardée");
                }
            } catch (Exception ex) {
                handleError(ex, "sauvegarde de clé");
            }
        });

        /* Gestion RSA séparée */
        Button btnLoadPub = createIconButton("\uf07c", " Charger publique");
        Button btnLoadPriv = createIconButton("\uf07c", " Charger privée");

        btnLoadPub.setOnAction(e -> {
            try {
                if (!(crypto instanceof CryptoRSA rsa)) return;
                File f = chooseFileOpen(stage, "Charger clé publique");
                if (f != null) {
                    rsa.loadPublicKey(f);
                    refreshKeyDisplay();
                    info("Succès", "Clé publique chargée");
                }
            } catch (Exception ex) {
                handleError(ex, "chargement clé publique");
            }
        });

        btnLoadPriv.setOnAction(e -> {
            try {
                if (!(crypto instanceof CryptoRSA rsa)) return;
                File f = chooseFileOpen(stage, "Charger clé privée");
                if (f != null) {
                    rsa.loadPrivateKey(f);
                    refreshKeyDisplay();
                    info("Succès", "Clé privée chargée");
                }
            } catch (Exception ex) {
                handleError(ex, "chargement clé privée");
            }
        });

        rsaKeyManagement = new VBox(8,
                new Label("Chargement séparé"),
                new HBox(8, btnLoadPub, btnLoadPriv)
        );
        rsaKeyManagement.setVisible(false);
        rsaKeyManagement.setManaged(false);

        VBox keyBox = new VBox(10,
                new Label("GESTION DES CLÉS"),
                new HBox(10, btnGenKey, btnLoadKey, btnSaveKey),
                rsaKeyManagement,
                taAESKey, taRSAPublicKey, taRSAPrivateKey
        );
        keyBox.setStyle("-fx-background-color: rgba(0,0,0,0.3); -fx-padding: 15; -fx-background-radius: 8;");

        /* Opérations */
        rbEncrypt = new RadioButton("Chiffrer");
        rbDecrypt = new RadioButton("Déchiffrer");
        ToggleGroup tgCrypto = new ToggleGroup();
        rbEncrypt.setToggleGroup(tgCrypto);
        rbDecrypt.setToggleGroup(tgCrypto);
        rbEncrypt.setSelected(true);

        btnProcess = createIconButton("\uf023", " Chiffrer");
        rbEncrypt.setOnAction(e -> btnProcess.setText("\uf023 Chiffrer"));
        rbDecrypt.setOnAction(e -> btnProcess.setText("\uf09c Déchiffrer"));

        taInput = createStyledTextArea("Texte à traiter...", 6);
        taOutput = createStyledTextArea("Résultat...", 6);
        taOutput.setEditable(false);

        Button btnLoadText = createIconButton("\uf093", " Importer");
        Button btnSaveText = createIconButton("\uf019", " Sauvegarder");
        Button btnClear = createIconButton("\uf1f8", " Effacer");

        btnLoadText.setOnAction(e -> {
            try {
                File f = chooseFileOpen(stage, "Importer texte");
                if (f != null) taInput.setText(crypto.loadText(f));
            } catch (Exception ex) {
                handleError(ex, "importation");
            }
        });

        btnProcess.setOnAction(e -> {
            try {
                if (rbEncrypt.isSelected()) {
                    taOutput.setText(crypto.encrypt(taInput.getText()));
                    info("Succès", "Chiffrement réussi");
                } else {
                    taOutput.setText(crypto.decrypt(taInput.getText()));
                    info("Succès", "Déchiffrement réussi");
                }
            } catch (Exception ex) {
                handleError(ex, rbEncrypt.isSelected() ? "chiffrement" : "déchiffrement");
            }
        });

        btnSaveText.setOnAction(e -> {
            try {
                String name = String.format("%s_%s_%s",
                        rbEncrypt.isSelected() ? "Encrypted" : "Decrypted",
                        cbCryptoType.getValue(), cbCryptoMode.getValue());
                File f = chooseFileSave(stage, "Sauvegarder", name);
                if (f != null) {
                    crypto.saveText(taOutput.getText(), f);
                    info("Succès", "Sauvegardé");
                }
            } catch (Exception ex) {
                handleError(ex, "sauvegarde");
            }
        });

        btnClear.setOnAction(e -> {
            taInput.clear();
            taOutput.clear();
        });

        VBox opBox = new VBox(10,
                new Label("OPÉRATION"),
                new HBox(15, rbEncrypt, rbDecrypt),
                new Label("Entrée"), taInput, btnLoadText,
                new Label("Sortie"), taOutput,
                new HBox(10, btnProcess, btnSaveText, btnClear)
        );
        opBox.setStyle("-fx-background-color: rgba(0,0,0,0.3); -fx-padding: 15; -fx-background-radius: 8;");
        VBox.setVgrow(taInput, Priority.ALWAYS);
        VBox.setVgrow(taOutput, Priority.ALWAYS);

        cbCryptoType.setOnAction(e -> {
            CryptoType type = cbCryptoType.getValue();
            updateKeySizes(type);
            if (type == CryptoType.AES) {
                crypto = new CryptoAES();
                showAESKeys();
                rsaKeyManagement.setVisible(false);
                rsaKeyManagement.setManaged(false);
            } else {
                crypto = new CryptoRSA();
                showRSAKeys();
                rsaKeyManagement.setVisible(true);
                rsaKeyManagement.setManaged(true);
            }
            crypto.setMode(cbCryptoMode.getValue());
            clearKeys();
        });

        HBox mainBox = new HBox(20, configBox, keyBox, opBox);
        HBox.setHgrow(opBox, Priority.ALWAYS);
        VBox container = new VBox(mainBox);
        container.setPadding(new Insets(15));
        VBox.setVgrow(mainBox, Priority.ALWAYS);
        return container;
    }

    /* =========================
       ONGLET SIGNATURE RSA
    ========================= */
    private VBox createSignatureTab(Stage stage) {
        Label lblInfo = new Label("⚠ Assurez-vous d'avoir généré ou chargé une paire de clés RSA dans l'onglet Chiffrement");
        lblInfo.setStyle("-fx-text-fill: orange; -fx-font-size: 12px;");

        rbSign = new RadioButton("Signer un message");
        rbVerify = new RadioButton("Vérifier une signature");
        ToggleGroup tgSign = new ToggleGroup();
        rbSign.setToggleGroup(tgSign);
        rbVerify.setToggleGroup(tgSign);
        rbSign.setSelected(true);

        btnSignProcess = createIconButton("\uf040", " Signer");
        rbSign.setOnAction(e -> btnSignProcess.setText("\uf040 Signer"));
        rbVerify.setOnAction(e -> btnSignProcess.setText("\uf00c Vérifier"));

        taSignInput = createStyledTextArea("Message à signer/vérifier...", 5);
        taSignOutput = createStyledTextArea("Résultat...", 3);
        taSignOutput.setEditable(false);

        taSignature = createStyledTextArea("Signature (Base64)", 4);

        Button btnLoadSig = createIconButton("\uf07c", " Charger signature");
        Button btnSaveSig = createIconButton("\uf0c7", " Sauvegarder signature");

        btnLoadSig.setOnAction(e -> {
            try {
                File f = chooseFileOpen(stage, "Charger signature");
                if (f != null) taSignature.setText(Files.readString(f.toPath()));
            } catch (Exception ex) {
                handleError(ex, "chargement signature");
            }
        });

        btnSaveSig.setOnAction(e -> {
            try {
                File f = chooseFileSave(stage, "Sauvegarder signature", "Signature_RSA");
                if (f != null) Files.writeString(f.toPath(), taSignature.getText());
                info("Succès", "Signature sauvegardée");
            } catch (Exception ex) {
                handleError(ex, "sauvegarde signature");
            }
        });

        btnSignProcess.setOnAction(e -> {
            try {
                if (!(crypto instanceof CryptoRSA rsa)) {
                    error("Chargez d'abord une paire de clés RSA dans l'onglet Chiffrement");
                    return;
                }

                if (rbSign.isSelected()) {
                    String sig = rsa.signToBase64(taSignInput.getText());
                    taSignature.setText(sig);
                    taSignOutput.setText("✓ Signature générée avec succès");
                    info("Succès", "Message signé");
                } else {
                    if (taSignature.getText().trim().isEmpty()) {
                        error("Veuillez saisir ou charger une signature");
                        return;
                    }
                    boolean valid = rsa.verifyFromBase64(taSignInput.getText(), taSignature.getText());
                    if (valid) {
                        taSignOutput.setText("✓ SIGNATURE VALIDE\n\nLa signature correspond au message.");
                        info("Vérification", "✓ SIGNATURE VALIDE");
                    } else {
                        taSignOutput.setText("✗ SIGNATURE INVALIDE\n\nLa signature ne correspond PAS.");
                        error("✗ SIGNATURE INVALIDE");
                    }
                }
            } catch (Exception ex) {
                handleError(ex, rbSign.isSelected() ? "signature" : "vérification");
            }
        });

        VBox container = new VBox(15,
                lblInfo,
                new Label("MODE"),
                new HBox(15, rbSign, rbVerify),
                new Label("MESSAGE"),
                taSignInput,
                new Label("SIGNATURE"),
                taSignature,
                new HBox(10, btnLoadSig, btnSaveSig),
                new Label("RÉSULTAT"),
                taSignOutput,
                btnSignProcess
        );
        container.setPadding(new Insets(15));
        container.setStyle("-fx-background-color: rgba(0,0,0,0.3); -fx-background-radius: 8;");
        VBox.setVgrow(taSignInput, Priority.ALWAYS);
        return container;
    }

    /* =========================
       ONGLET HACHAGE
    ========================= */
    private VBox createHashTab(Stage stage) {
        cbHashAlgorithm = new ComboBox<>();
        cbHashAlgorithm.getItems().addAll(HashAlgorithm.values());
        cbHashAlgorithm.setValue(HashAlgorithm.SHA256);

        taHashInput = createStyledTextArea("Texte à hacher...", 6);
        taHashOutput = createStyledTextArea("Hash (hexadécimal)", 3);
        taHashOutput.setEditable(false);

        lblHashInfo = new Label("");
        lblHashInfo.setStyle("-fx-text-fill: white; -fx-font-size: 11px;");

        Button btnHash = createIconButton("\uf292", " Calculer Hash");
        Button btnHashFile = createIconButton("\uf15b", " Hacher un fichier");
        Button btnSaveHash = createIconButton("\uf0c7", " Sauvegarder Hash");
        Button btnClearHash = createIconButton("\uf1f8", " Effacer");

        btnHash.setOnAction(e -> {
            try {
                String hash = HashService.hashText(taHashInput.getText(), cbHashAlgorithm.getValue());
                taHashOutput.setText(hash);
                int size = HashService.getHashSize(cbHashAlgorithm.getValue());
                lblHashInfo.setText(String.format("Algorithme: %s | Taille: %d bits | Longueur hex: %d caractères",
                        cbHashAlgorithm.getValue(), size, hash.length()));
                info("Succès", "Hash calculé");
            } catch (Exception ex) {
                handleError(ex, "hachage");
            }
        });

        btnHashFile.setOnAction(e -> {
            try {
                File f = chooseFileOpen(stage, "Sélectionner fichier à hacher");
                if (f != null) {
                    String hash = HashService.hashFile(f, cbHashAlgorithm.getValue());
                    taHashOutput.setText(hash);
                    taHashInput.setText("[Fichier: " + f.getName() + "]");
                    int size = HashService.getHashSize(cbHashAlgorithm.getValue());
                    lblHashInfo.setText(String.format("Fichier: %s | Algorithme: %s | Hash: %d bits",
                            f.getName(), cbHashAlgorithm.getValue(), size));
                    info("Succès", "Fichier haché");
                }
            } catch (Exception ex) {
                handleError(ex, "hachage de fichier");
            }
        });

        btnSaveHash.setOnAction(e -> {
            try {
                String name = String.format("Hash_%s", cbHashAlgorithm.getValue());
                File f = chooseFileSave(stage, "Sauvegarder hash", name);
                if (f != null) {
                    Files.writeString(f.toPath(), taHashOutput.getText());
                    info("Succès", "Hash sauvegardé");
                }
            } catch (Exception ex) {
                handleError(ex, "sauvegarde hash");
            }
        });

        btnClearHash.setOnAction(e -> {
            taHashInput.clear();
            taHashOutput.clear();
            taHashCompare.clear();
            lblHashInfo.setText("");
        });

        /* Vérification */
        taHashCompare = createStyledTextArea("Hash à comparer (optionnel)", 2);
        Button btnVerifyHash = createIconButton("\uf00c", " Vérifier");

        btnVerifyHash.setOnAction(e -> {
            try {
                if (taHashCompare.getText().trim().isEmpty()) {
                    error("Saisissez un hash à comparer");
                    return;
                }
                boolean valid = HashService.verifyHash(taHashInput.getText(),
                        taHashCompare.getText(), cbHashAlgorithm.getValue());
                if (valid) {
                    info("Vérification", "✓ Les hashs correspondent !");
                } else {
                    error("✗ Les hashs ne correspondent PAS");
                }
            } catch (Exception ex) {
                handleError(ex, "vérification hash");
            }
        });

        VBox container = new VBox(15,
                new Label("ALGORITHME DE HACHAGE"),
                cbHashAlgorithm,
                new Label("TEXTE À HACHER"),
                taHashInput,
                new HBox(10, btnHash, btnHashFile),
                new Label("RÉSULTAT (HASH)"),
                taHashOutput,
                lblHashInfo,
                new HBox(10, btnSaveHash, btnClearHash),
                new Separator(),
                new Label("VÉRIFICATION"),
                taHashCompare,
                btnVerifyHash
        );
        container.setPadding(new Insets(15));
        container.setStyle("-fx-background-color: rgba(0,0,0,0.3); -fx-background-radius: 8;");
        VBox.setVgrow(taHashInput, Priority.ALWAYS);
        return container;
    }

    /* =========================
       ONGLET DIFFIE-HELLMAN
    ========================= */
    private VBox createDiffieHellmanTab(Stage stage) {
        cbDHKeySize = new ComboBox<>();
        cbDHKeySize.getItems().addAll(1024, 2048, 3072);
        cbDHKeySize.setValue(2048);

        taDHPublicKey = createStyledTextArea("Votre clé publique (à partager)", 4);
        taDHPublicKey.setEditable(false);

        taDHOtherPublicKey = createStyledTextArea("Clé publique de l'autre partie", 4);

        taDHSharedSecret = createStyledTextArea("Secret partagé (hexadécimal)", 5);
        taDHSharedSecret.setEditable(false);

        lblDHStatus = new Label("Status: Aucune clé générée");
        lblDHStatus.setStyle("-fx-text-fill: orange; -fx-font-size: 12px;");

        Button btnDHGenerate = createIconButton("\uf084", " Générer mes clés DH");
        Button btnDHSavePub = createIconButton("\uf0c7", " Sauvegarder ma clé publique");
        Button btnDHLoadOther = createIconButton("\uf07c", " Charger clé de l'autre");
        Button btnDHCompute = createIconButton("\uf0e7", " Calculer secret partagé");
        Button btnDHDeriveAES = createIconButton("\uf084", " Dériver clé AES");

        btnDHGenerate.setOnAction(e -> {
            try {
                dhService.generateKeys(cbDHKeySize.getValue());
                taDHPublicKey.setText(dhService.getPublicKeyAsBase64());
                lblDHStatus.setText("✓ Clés générées. Partagez votre clé publique.");
                lblDHStatus.setStyle("-fx-text-fill: lime; -fx-font-size: 12px;");
                info("Succès", "Clés Diffie-Hellman générées");
            } catch (Exception ex) {
                handleError(ex, "génération DH");
            }
        });

        btnDHSavePub.setOnAction(e -> {
            try {
                File f = chooseFileSave(stage, "Sauvegarder clé publique DH", "DH_PublicKey");
                if (f != null) {
                    dhService.savePublicKey(f);
                    info("Succès", "Clé publique sauvegardée");
                }
            } catch (Exception ex) {
                handleError(ex, "sauvegarde clé DH");
            }
        });

        btnDHLoadOther.setOnAction(e -> {
            try {
                File f = chooseFileOpen(stage, "Charger clé publique de l'autre");
                if (f != null) {
                    taDHOtherPublicKey.setText(Files.readString(f.toPath()));
                    info("Info", "Clé chargée. Cliquez sur 'Calculer secret partagé'");
                }
            } catch (Exception ex) {
                handleError(ex, "chargement clé DH");
            }
        });

        btnDHCompute.setOnAction(e -> {
            try {
                if (taDHOtherPublicKey.getText().trim().isEmpty()) {
                    error("Veuillez saisir ou charger la clé publique de l'autre partie");
                    return;
                }
                dhService.computeSharedSecret(taDHOtherPublicKey.getText());
                taDHSharedSecret.setText(dhService.getSharedSecretAsHex());
                lblDHStatus.setText("✓ Secret partagé calculé ! " + dhService.getSharedSecretInfo());
                lblDHStatus.setStyle("-fx-text-fill: lime; -fx-font-size: 12px;");
                info("Succès", "Secret partagé établi");
            } catch (Exception ex) {
                handleError(ex, "calcul secret partagé");
            }
        });

        btnDHDeriveAES.setOnAction(e -> {
            try {
                String aesKey = dhService.deriveAESKey(256);
                String msg = "Clé AES 256 bits dérivée:\n\n" + aesKey +
                        "\n\nVous pouvez utiliser cette clé dans l'onglet Chiffrement";
                Alert a = new Alert(Alert.AlertType.INFORMATION, msg);
                a.setHeaderText("Clé AES dérivée");
                TextArea ta = new TextArea(aesKey);
                ta.setEditable(false);
                a.getDialogPane().setExpandableContent(ta);
                a.showAndWait();
            } catch (Exception ex) {
                handleError(ex, "dérivation clé AES");
            }
        });

        VBox guide = new VBox(5,
                new Label("📖 GUIDE D'UTILISATION:"),
                new Label("1. Générez vos clés DH"),
                new Label("2. Partagez votre clé publique à l'autre partie"),
                new Label("3. Recevez la clé publique de l'autre partie"),
                new Label("4. Calculez le secret partagé"),
                new Label("5. Les deux parties obtiennent le MÊME secret !")
        );
        guide.setStyle("-fx-background-color: rgba(155,1,1,0.2); -fx-padding: 10; -fx-background-radius: 5;");

        VBox container = new VBox(15,
                new Label("ÉCHANGE DE CLÉS DIFFIE-HELLMAN"),
                guide,
                new Label("Taille de clé"), cbDHKeySize,
                btnDHGenerate,
                new Label("VOTRE CLÉ PUBLIQUE (à partager)"),
                taDHPublicKey,
                btnDHSavePub,
                new Label("CLÉ PUBLIQUE DE L'AUTRE PARTIE"),
                taDHOtherPublicKey,
                btnDHLoadOther,
                btnDHCompute,
                new Label("SECRET PARTAGÉ"),
                taDHSharedSecret,
                lblDHStatus,
                btnDHDeriveAES
        );
        container.setPadding(new Insets(15));
        container.setStyle("-fx-background-color: rgba(0,0,0,0.3); -fx-background-radius: 8;");
        return container;
    }

    /* =========================
       UTILITAIRES
    ========================= */
    private TextArea createStyledTextArea(String prompt, int rows) {
        TextArea ta = new TextArea();
        ta.setPromptText(prompt);
        ta.setPrefRowCount(rows);
        ta.setWrapText(true);
        ta.setStyle("-fx-control-inner-background: rgba(255,255,255,0.9); -fx-text-fill: #1a1a1a;");
        return ta;
    }

    private Button createIconButton(String icon, String text) {
        Button btn = new Button(icon + text);
        btn.setStyle("-fx-font-family: 'FontAwesome'; -fx-font-weight: bold;");
        return btn;
    }

    private void loadFontAwesome() {
        try {
            InputStream is = getClass().getResourceAsStream("/fonts/fontawesome-webfont.ttf");
            if (is != null) Font.loadFont(is, 14);
        } catch (Exception e) {
            System.err.println("FontAwesome: " + e.getMessage());
        }
    }

    private void updateKeySizes(CryptoType type) {
        cbKeySize.getItems().clear();
        for (KeySize ks : KeySize.values())
            if (ks.getType() == type)
                cbKeySize.getItems().add(ks);
        cbKeySize.setValue(cbKeySize.getItems().get(0));
    }

    private void refreshKeyDisplay() {
        clearKeys();
        if (crypto instanceof CryptoAES aes)
            taAESKey.setText(aes.getKeyAsBase64());
        if (crypto instanceof CryptoRSA rsa) {
            taRSAPublicKey.setText(rsa.getPublicKeyAsBase64());
            taRSAPrivateKey.setText(rsa.getPrivateKeyAsBase64());
        }
    }

    private void showAESKeys() {
        taAESKey.setVisible(true);
        taAESKey.setManaged(true);
        taRSAPublicKey.setVisible(false);
        taRSAPublicKey.setManaged(false);
        taRSAPrivateKey.setVisible(false);
        taRSAPrivateKey.setManaged(false);
    }

    private void showRSAKeys() {
        taAESKey.setVisible(false);
        taAESKey.setManaged(false);
        taRSAPublicKey.setVisible(true);
        taRSAPublicKey.setManaged(true);
        taRSAPrivateKey.setVisible(true);
        taRSAPrivateKey.setManaged(true);
    }

    private void clearKeys() {
        taAESKey.clear();
        taRSAPublicKey.clear();
        taRSAPrivateKey.clear();
    }

    private File chooseFileOpen(Stage stage, String title) {
        FileChooser fc = new FileChooser();
        fc.setTitle(title);
        fc.getExtensionFilters().add(new FileChooser.ExtensionFilter("TXT", "*.txt"));
        return fc.showOpenDialog(stage);
    }

    private File chooseFileSave(Stage stage, String title, String name) {
        FileChooser fc = new FileChooser();
        fc.setTitle(title);
        fc.setInitialFileName(name + ".txt");
        return fc.showSaveDialog(stage);
    }

    private void error(String msg) {
        Alert alert = new Alert(Alert.AlertType.ERROR, msg);
        alert.setHeaderText("Erreur");
        alert.showAndWait();
    }

    private void info(String title, String msg) {
        Alert a = new Alert(Alert.AlertType.INFORMATION, msg);
        a.setHeaderText(title);
        a.showAndWait();
    }

    private void handleError(Exception ex, String operation) {
        String userMessage;
        if (ex.getMessage() != null && ex.getMessage().toLowerCase().contains("badpadding")) {
            userMessage = "Erreur lors du " + operation + ".\n\nClé incorrecte ou données corrompues.";
        } else if (ex.getMessage() != null && ex.getMessage().toLowerCase().contains("key")) {
            userMessage = "Erreur lors du " + operation + ".\n\nVérifiez que la clé est chargée.";
        } else if (ex instanceof java.io.FileNotFoundException) {
            userMessage = "Fichier introuvable.";
        } else if (ex instanceof IllegalStateException) {
            userMessage = ex.getMessage();
        } else {
            userMessage = "Erreur lors du " + operation + ".\n\nVérifiez vos données.";
        }
        System.err.println("[ERREUR - " + operation + "] " + ex.getClass().getName() + ": " + ex.getMessage());
        error(userMessage);
    }

    public static void main(String[] args) {
        launch(args);
    }
}