let key;
let iv;

async function generateKey() {
    try {
        key = await window.crypto.subtle.generateKey(
            { name: "AES-CBC", length: 128 },
            true,
            ["encrypt", "decrypt"]
        );

        // Export the key to JWK format
        const exportedKey = await window.crypto.subtle.exportKey("jwk", key);

        // Store the key in local storage
        localStorage.setItem("cryptoKey", JSON.stringify(exportedKey));
    } catch (error) {
        alert("Error generating key: " + error.message);
    }
}

async function importKey() {
    try {
        const cryptoKey = localStorage.getItem("cryptoKey");
        if (!cryptoKey) {
            throw new Error("Crypto key not found.");
        }

        const parsedKey = JSON.parse(cryptoKey);
        if (!parsedKey.kty) {
            throw new Error("Invalid crypto key format.");
        }

        key = await window.crypto.subtle.importKey(
            "jwk",
            parsedKey,
            { name: "AES-CBC", length: 128 },
            true,
            ["encrypt", "decrypt"]
        );
    } catch (error) {
        alert("Error importing key: " + error.message);
    }
}

async function encryptString(str) {
    try {
        const encodedString = new TextEncoder().encode(str);
        iv = window.crypto.getRandomValues(new Uint8Array(16));
        const encryptedData = await window.crypto.subtle.encrypt(
            { name: "AES-CBC", iv: iv },
            key,
            encodedString
        );

        // Store the IV in local storage
        localStorage.setItem("iv", JSON.stringify(Array.from(iv)));

        return Array.prototype.map.call(new Uint8Array(encryptedData), x => ('00' + x.toString(16)).slice(-2)).join('');
    } catch (error) {
        alert("Error encrypting string: " + error.message);
    }
}

async function decryptString(encryptedData) {
    try {
        // Retrieve the IV from local storage
        const storedIv = localStorage.getItem("iv");
        if (!storedIv) {
            throw new Error("IV not found.");
        }
        iv = new Uint8Array(JSON.parse(storedIv));

        if (!key || !iv) {
            throw new Error("Key or IV is missing.");
        }

        const decryptedData = await window.crypto.subtle.decrypt(
            { name: "AES-CBC", iv: iv },
            key,
            encryptedData
        );
        return new TextDecoder().decode(decryptedData);
    } catch (error) {
        alert("Error decrypting string: " + error.message);
        return null; // Return null to indicate decryption failure
    }
}

async function encrypt() {
    try {
        await generateKey();
        const input = document.getElementById('input').value;
        const encryptedHex = await encryptString(input);

        // Export the key to JWK format
        const exportedKey = await window.crypto.subtle.exportKey("jwk", key);

        // Create a Blob with the encrypted data, the IV, and the key
        const blob = new Blob([JSON.stringify({ encryptedData: encryptedHex, iv: Array.from(iv), key: exportedKey })], { type: 'application/json' });

        // Create a temporary URL for the Blob
        const url = window.URL.createObjectURL(blob);

        // Set the download link href and display it
        const downloadLink = document.getElementById('downloadLink');
        downloadLink.href = url;
        downloadLink.download = 'encrypted_data.txt';
        downloadLink.style.display = 'block';

        // Provide feedback to the user
        document.getElementById('output').innerText = "Encrypted data ready for download.";
    } catch (error) {
        alert("Error during encryption: " + error.message);
    }
}

async function decrypt() {
    try {
        // Retrieve the encrypted data from the file input
        const fileInput = document.getElementById('fileInput');
        const file = fileInput.files[0];

        if (!file) {
            alert("Please select a file.");
            return;
        }

        const reader = new FileReader();

        reader.onload = async function () {
            const data = JSON.parse(reader.result);
            const encryptedHex = data.encryptedData;
            const encryptedData = new Uint8Array(encryptedHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

            // Import the key from the file
            key = await window.crypto.subtle.importKey(
                "jwk",
                data.key,
                { name: "AES-CBC", length: 128 },
                true,
                ["encrypt", "decrypt"]
            );

            // Retrieve the IV from the file
            iv = new Uint8Array(data.iv);

            const decryptedString = await decryptString(encryptedData);
            document.getElementById('output').innerText = "Decrypted: " + decryptedString;
        };

        reader.readAsText(file);
    } catch (error) {
        alert("Error during decryption: " + error.message);
    }
}
