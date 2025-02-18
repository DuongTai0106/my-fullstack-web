import express from "express";
import dotenv from "dotenv/config";
import cors from "cors";
import cookieParser from "cookie-parser";
import connectDB from "./config/mongodb.js";
import authRouter from "./routes/authRoutes.js";
import userRouter from "./routes/userRoutes.js";
const app = express();

const allowedOrigins = ["http://localhost:5173"];

//middleware
app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));
app.use(cors({ origin: allowedOrigins, credentials: true }));

//API Endpoint
app.use("/", authRouter);
app.use("/user", userRouter);

const port = 8000;
connectDB();
app.listen(port, () => console.log(`Server is running on ${port}`));
