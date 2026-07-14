// Import necessary Firebase modular SDK components
import { initializeApp } from "firebase/app";
import { getAuth, GoogleAuthProvider } from "firebase/auth";

// Firebase configuration object containing project credentials and keys
/**
 * Configuration: firebaseConfig
 * Description: Identity provider credentials and project identifiers 
 *              for the SIEM Watchtower Firebase project. Enables 
 *              biometric-grade identity verification and session logic.
 */
const firebaseConfig = {
  apiKey: "AIzaSyDEDJWBr5UkgVM9FR1H7D2a0Uuvir3kBLE",
  authDomain: "siem-watchtower.firebaseapp.com",
  projectId: "siem-watchtower",
  storageBucket: "siem-watchtower.firebasestorage.app",
  messagingSenderId: "673314158815",
  appId: "1:673314158815:web:84bc12fd5427391476516a",
  measurementId: "G-6JCKHG1BLC"
};

// Initializes the Firebase application instance
const app = initializeApp(firebaseConfig);

// Exports the authentication service instance for the app
export const auth = getAuth(app);

// Exports the Google Authentication provider instance
const googleProvider = new GoogleAuthProvider();
googleProvider.setCustomParameters({
  prompt: 'select_account'
});
export const provider = googleProvider;
