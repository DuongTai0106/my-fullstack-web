import mongoose from "mongoose";
const connectDB = async () => {
    await mongoose
      .connect(process.env.MONGO_URL)
      .then(() => console.log("Database is connected"))
      .catch((err) => console.log("Database is not connected", err));
}

export default connectDB;