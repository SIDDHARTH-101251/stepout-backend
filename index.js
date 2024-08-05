const express = require("express");
const cors = require("cors");
const pool = require("./db"); // Import pool from db.js
const argon2 = require("argon2");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const port = 8080;

// Create express app
const app = express();

// Middleware
app.use(express.json()); // Parsing to JSON
app.use(cors()); // Handling requests from other origins

// Authentication Middleware
const authenticate = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Extract token part

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // Attach decoded user info to request
    console.log("Authenticated user:", req.user); // For debugging
    next();
  } catch (err) {
    res.status(400).json({ error: "Invalid token." });
  }
};

const authorize = (role) => {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.status(403).json({ error: "Access denied." });
    }
    next();
  };
};

// Create user table if it does not exist
const createUserTable = async () => {
  try {
    await pool.query(
      `CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'user'
      )`
    );
    console.log("User Table Created Successfully!");
  } catch (err) {
    console.error("Error creating user table:", err);
  }
};

createUserTable();

// Create train table if it does not exist
const createTrainTable = async () => {
  try {
    await pool.query(
      `CREATE TABLE IF NOT EXISTS train (
        id SERIAL PRIMARY KEY,
        train_name VARCHAR(50) NOT NULL,
        source_station VARCHAR(50) NOT NULL,
        destination_station VARCHAR(50) NOT NULL,
        total_seats INTEGER NOT NULL
      )`
    );
    console.log("Train Table Created Successfully!");
  } catch (err) {
    console.error("Error creating train table:", err);
  }
};

createTrainTable();

// Create bookings table if it does not exist
const createBookingsTable = async () => {
  try {
    await pool.query(
      `CREATE TABLE IF NOT EXISTS bookings (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        train_id INTEGER REFERENCES train(id) ON DELETE CASCADE,
        seats_booked INTEGER NOT NULL,
        booking_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )`
    );
    console.log("Bookings Table Created Successfully!");
  } catch (err) {
    console.error("Error creating bookings table:", err);
  }
};

createBookingsTable();

// Handling user signup
const jwtSecret = process.env.JWT_SECRET || "your_jwt_secret"; // Store in environment variables

// POST /signup route
app.post("/signup", async (req, res) => {
  const { username, password, role } = req.body;

  if (!username || !password) {
    return res
      .status(400)
      .json({ error: "Username and password are required" });
  }

  try {
    // Check if the user already exists
    const userResult = await pool.query(
      "SELECT * FROM users WHERE username = $1",
      [username]
    );
    if (userResult.rows.length > 0) {
      return res.status(400).json({ error: "Username already exists" });
    }

    // Hash the password
    const hashedPassword = await argon2.hash(password);

    // Default to 'user' if role is not provided
    const userRole = role || "user";

    // Insert the new user into the database
    await pool.query(
      "INSERT INTO users (username, password, role) VALUES ($1, $2, $3)",
      [username, hashedPassword, userRole]
    );

    // Generate a JWT token
    const token = jwt.sign({ username, role: userRole }, jwtSecret, {
      expiresIn: "1h",
    });

    res.status(201).json({ message: "User registered successfully", token });
  } catch (err) {
    console.error("Error registering user:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// POST /login route
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res
      .status(400)
      .json({ error: "Username and password are required" });
  }

  try {
    // Check if the user exists
    const userResult = await pool.query(
      "SELECT * FROM users WHERE username = $1",
      [username]
    );

    if (userResult.rows.length === 0) {
      return res.status(400).json({ error: "Invalid username or password" });
    }

    const user = userResult.rows[0];

    // Verify the password
    const isPasswordValid = await argon2.verify(user.password, password);
    if (!isPasswordValid) {
      return res.status(400).json({ error: "Invalid username or password" });
    }

    // Generate a JWT token
    const token = jwt.sign({ username, role: user.role }, jwtSecret, {
      expiresIn: "1h",
    });

    res.status(200).json({ message: "Login successful", token });
  } catch (err) {
    console.error("Error during login:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// POST /trains route
app.post(
  "/trains",
  authenticate,
  authorize("administrator"), // Ensure the role matches
  async (req, res) => {
    const { train_name, source_station, destination_station, total_seats } =
      req.body;

    if (
      !train_name ||
      !source_station ||
      !destination_station ||
      !total_seats
    ) {
      return res.status(400).json({ error: "All fields are required" });
    }

    try {
      await pool.query(
        "INSERT INTO train (train_name, source_station, destination_station, total_seats) VALUES ($1, $2, $3, $4)",
        [train_name, source_station, destination_station, total_seats]
      );
      res.status(201).json({ message: "Train added successfully" });
    } catch (err) {
      console.error("Error adding train:", err);
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

// PUT /trains/:id route
app.put(
  "/trains/:id",
  authenticate,
  authorize("administrator"),
  async (req, res) => {
    const { id } = req.params;
    const { train_name, source_station, destination_station, total_seats } =
      req.body;

    if (
      !train_name &&
      !source_station &&
      !destination_station &&
      !total_seats
    ) {
      return res
        .status(400)
        .json({ error: "At least one field is required to update" });
    }

    try {
      const updateFields = [];
      const updateValues = [];
      let query = "UPDATE train SET ";

      if (train_name) {
        updateFields.push("train_name = $1");
        updateValues.push(train_name);
      }
      if (source_station) {
        updateFields.push("source_station = $2");
        updateValues.push(source_station);
      }
      if (destination_station) {
        updateFields.push("destination_station = $3");
        updateValues.push(destination_station);
      }
      if (total_seats) {
        updateFields.push("total_seats = $4");
        updateValues.push(total_seats);
      }

      query += updateFields.join(", ") + " WHERE id = $5";
      updateValues.push(id);

      await pool.query(query, updateValues);
      res.status(200).json({ message: "Train details updated successfully" });
    } catch (err) {
      console.error("Error updating train details:", err);
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

// DELETE /trains/:id route
app.delete(
  "/trains/:id",
  authenticate,
  authorize("administrator"),
  async (req, res) => {
    const { id } = req.params;

    try {
      const result = await pool.query("DELETE FROM train WHERE id = $1", [id]);

      if (result.rowCount === 0) {
        return res.status(404).json({ error: "Train not found" });
      }

      res.status(200).json({ message: "Train removed successfully" });
    } catch (err) {
      console.error("Error removing train:", err);
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

// GET /trains route
app.get("/trains", async (req, res) => {
  const { source_station, destination_station } = req.query;

  if (!source_station || !destination_station) {
    return res
      .status(400)
      .json({ error: "Source and destination stations are required" });
  }

  try {
    const result = await pool.query(
      "SELECT * FROM train WHERE source_station = $1 AND destination_station = $2",
      [source_station, destination_station]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "No trains found" });
    }

    res.status(200).json(result.rows);
  } catch (err) {
    console.error("Error retrieving trains:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /trains/:id/seats route
app.get("/trains/:id/seats", async (req, res) => {
  const { id } = req.params;

  try {
    const trainResult = await pool.query(
      "SELECT total_seats FROM train WHERE id = $1",
      [id]
    );
    const bookingResult = await pool.query(
      "SELECT SUM(seats_booked) AS booked_seats FROM bookings WHERE train_id = $1",
      [id]
    );

    if (trainResult.rows.length === 0) {
      return res.status(404).json({ message: "Train not found" });
    }

    const totalSeats = trainResult.rows[0].total_seats;
    const bookedSeats = bookingResult.rows[0].booked_seats || 0;
    const availableSeats = totalSeats - bookedSeats;

    res.status(200).json({ availableSeats });
  } catch (err) {
    console.error("Error retrieving seat availability:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// POST /bookings route
app.post("/bookings", async (req, res) => {
  const { user_id, train_id, seats_booked } = req.body;

  if (!user_id || !train_id || !seats_booked) {
    return res
      .status(400)
      .json({ error: "User ID, Train ID, and Seats Booked are required" });
  }

  try {
    const trainResult = await pool.query(
      "SELECT total_seats FROM train WHERE id = $1",
      [train_id]
    );
    if (trainResult.rows.length === 0) {
      return res.status(404).json({ message: "Train not found" });
    }

    const bookingResult = await pool.query(
      "SELECT SUM(seats_booked) AS booked_seats FROM bookings WHERE train_id = $1",
      [train_id]
    );
    const totalSeats = trainResult.rows[0].total_seats;
    const bookedSeats = bookingResult.rows[0].booked_seats || 0;
    const availableSeats = totalSeats - bookedSeats;

    if (seats_booked > availableSeats) {
      return res.status(400).json({ error: "Not enough seats available" });
    }

    await pool.query(
      "INSERT INTO bookings (user_id, train_id, seats_booked) VALUES ($1, $2, $3)",
      [user_id, train_id, seats_booked]
    );

    res.status(201).json({ message: "Booking successful" });
  } catch (err) {
    console.error("Error creating booking:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /bookings/:id route
app.get("/bookings/:id", async (req, res) => {
  const { id } = req.params;

  try {
    const bookingResult = await pool.query(
      `SELECT b.id, b.user_id, u.username, b.train_id, t.train_name, t.source_station, t.destination_station, b.seats_booked, b.booking_time
       FROM bookings b
       JOIN users u ON b.user_id = u.id
       JOIN train t ON b.train_id = t.id
       WHERE b.id = $1`,
      [id]
    );

    if (bookingResult.rows.length === 0) {
      return res.status(404).json({ message: "Booking not found" });
    }

    res.status(200).json(bookingResult.rows[0]);
  } catch (err) {
    console.error("Error fetching booking details:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// DELETE /delete/user route
app.delete("/delete/user", async (req, res) => {
  try {
    await pool.query("DROP TABLE IF EXISTS users CASCADE");
    res.status(200).json({
      message: "Users table and all dependent objects dropped successfully",
    });
  } catch (err) {
    console.error("Error dropping users table:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

//get all users data
app.get("/usersdata", async (req, res) => {
  const response = await pool.query("SELECT * FROM users");
  res.send(response.rows);
});

app.listen(port, () => console.log(`Server has started on port: ${port}`));
