import express from "express";
import path from "path";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

const Port = 5000;
const app = express();



//Firestore connectivity
import admin from "./firebaseConfig.js";
const db = admin.firestore();
//----------------


app.set("view engine", "ejs");

//Middle ware
app.use(express.static(path.join(path.resolve(), "public")));
app.use(express.urlencoded({ extended: true }));//to get req.body working
app.use(cookieParser());

// Creating our own middleware
const isAuthenticated = async (req, res, next) => {
    const { token } = req.cookies;
    console.log(token);
    if (token) {
        const decodedToken = jwt.verify(token, "randomSecret")
        // console.log(decodedToken);

        // If user is already logged in then we can store its whole data in req.user and then can access it using req.user anywhere
        req.user = await db.collection("Users").doc(decodedToken._id).get();
        next();
    } else {
        return res.render("login");
    }
}

app.get("/logout", (req, res) => { // get req
    res.clearCookie("token");
    res.render("login");
});


// Request Methods: CRUD operations

//Home Page
app.get("/", isAuthenticated, (req, res) => {
    // console.log(req.user.data());
    res.render("logout");
});

app.get("/register", (req, res) => {
    res.render("register");
});


//Regiter
app.post("/register", async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ error: "Name and email are required fields." });
    }

    try {
        const dbRef = db.collection("Users");
        let userRef = await dbRef.where("userEmail", "==", email).limit(1).get();

        if (!userRef.empty) {
            console.log("User already registered. Please login.");
            return res.render("login", { message: "User already regitered with this id" });
        }

        console.log("Registering User");

        const hashedPassword = await bcrypt.hash(password, 10);
        await dbRef.add({
            userName: name,
            userEmail: email,
            userPassword: hashedPassword
        });

        return res.render("login");
    } catch (error) {
        console.error("Error registering user:", error);
        return res.status(500).json({ error: "An error occurred while regitering the user." });
    }
})

//Login api
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Email and Password are required fields." });
    }

    try {
        const dbRef = db.collection("Users");
        let userRef = await dbRef.where("userEmail", "==", email).limit(1).get();

        if (userRef.empty) {
            console.log("User not found, regiter here.");
            return res.status(404).render("register");
        }

        const isMatch = await bcrypt.compare(password, userRef.docs[0].data().userPassword);

        if (isMatch) {
            console.log("User id pass correct");
            const token = jwt.sign({ _id: userRef.docs[0].id }, "randomSecret");
            // console.log(token);

            res.cookie("token", token, {
                httpOnly: true,
                expires: new Date(Date.now() + 60 * 1000)
            });

            return res.render("logout");
        } else {
            console.log("Password Incorrect");
            return res.render("login", { message: "Incorrect Password!" })
        }

    } catch (error) {
        console.error("Error logging in the user:", error);
        return res.status(500).json({ error: "An error occurred while logging in the user." });
    }
});



// Port listening on 5000
app.listen(Port, () => {
    console.log("Server is up and running...");
})