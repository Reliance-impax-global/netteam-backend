require('dotenv').config({ path: '.env' });
const express = require("express");
const path = require("path");
const fs = require("fs");
const cors = require("cors");
const http = require("http");
const { Server } = require("socket.io");
const uuid = require("uuid");
const mongoose = require("mongoose");
const { ObjectId } = require("mongodb");
const multer = require("multer");
const { exec } = require("child_process");
const nodemailer = require("nodemailer");
const otpGenerator = require("otp-generator");
const paypal = require("paypal-rest-sdk");
const connectToMongo = require('./db');
const port = process.env.PORT;
const app = express();
const server = http.createServer(app);
const io = new Server(server);
const cloudinary = require('cloudinary').v2;
const jwt = require('jsonwebtoken');
const bcrypt = require("bcrypt");
const ffmpeg = require('fluent-ffmpeg');
const cookieParser = require("cookie-parser");
const bodyParser = require('body-parser');
const { body, validationResult } = require('express-validator');

//importing schemas
const Video = require('./models/videoSchema');
const UserInfo = require('./models/loginSchema');
const Message = require('./models/messageSchema');
const { userInfo } = require("os");
const { error } = require("console");

//acquire environment variables
const mongoURI = process.env.MONGODB_URI;
const cloudname = process.env.cloud_name;
const apikey = process.env.api_key;
const apisecret = process.env.api_secret;
const ffmpegPath = process.env.FFMPEG_PATH;
ffmpeg.setFfmpegPath(ffmpegPath);

// setting up middlewares
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
function verifyUser(req, res, next) {
  const token = req.cookies.token; // Retrieving the token from the HTTP-only cookie

  if (!token) {
    return res.status(403).json({ message: 'Token is not provided' });
  }
  // Using the token from the cookie for verification
  jwt.verify(token, process.env.JWT_SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Token is not valid' });
    } else {
      req.user = decoded; // Set req.user with the decoded token information
      console.log(decoded);
      next();
    }
  });
}

// Serve the static files
app.use(express.static("public"));
app.use(cors({ origin: process.env.CLIENT_URL }));
app.use(express.json());

const upload = multer({ dest: './temp' });
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);

});

// Cloudinary configuration
cloudinary.config({
  cloud_name: process.env.cloudname,
  api_key: process.env.apikey,
  api_secret: process.env.apisecret,
});

const startServer = async () => {

  // Set up MongoDB connection
  const connectToMongo = async () => {

    try {
      await mongoose.connect(mongoURI);
      // console.log("Connected to MongoDB successfully");
    }
    catch (error) {
      console.log(error);
      process.exit();
    }
  };
  connectToMongo();
  app.post(
    '/signup',
    [
      // Validation middleware
      body('password')
        .matches(/^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/)
        .withMessage('Password must contain at least 8 characters with one number, one alphabet, one symbol, and no spaces.'),
    ],
    async (req, res) => {
      try {
        const { name, email, password } = req.body;
        const existingUser = await UserInfo.findOne({ email });

        if (existingUser) {
          return res.status(409).json({ message: "User already exists" });
        }

        const errors = validationResult(req);
        if (!errors.isEmpty()) {
          return res.status(400).json({ errors: [{ msg: errors.array()[0].msg }] });
        }

        const hash = await bcrypt.hash(password, 13);
        const fancyId = email.split("@")[0];
        const token = jwt.sign({ email, name }, process.env.JWT_SECRET_KEY);
          const newUser = new UserInfo({ name, email, fancyId, password: hash });
          await newUser.save();
          const userData = await UserInfo.findOne({ email });

          res.cookie("token", token, {
            httpOnly: true,
          });

          return res.json({ msg: "User created successfully", _id: userData["_id"] });
        
      } catch (e) {
        console.error(e);
        return res.status(500).json({ msg: "Error creating user" });
      }
    }
  );


  app.post("/login", async (req, res) => {
    try {
      const { email, password } = req.body;
      const user = await UserInfo.findOne({ email });

      if (!user) {
        return res.status(401).json({ msg: "User not found" });
      }

      const isvalid = await bcrypt.compare(password, user.password);

      if (!isvalid) {
        return res.status(401).json({ msg: "Wrong details" });
      } else {
        const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET_KEY);
        // console.log(userEmail);
        res.cookie("token", token, {
          httpOnly: true,
        });

        return res.status(200).json({ msg: "Login successful" });
      }
    } catch (error) {
      console.error("Error during login:", error);
      return res.status(500).json({ message: "Error during login" });
    }
  });

  app.post("/postComment", verifyUser, async (req, res) => {
    try {
      const { videoId, comment } = req.body;
      const { email } = req.user;
      const id = new ObjectId();
      await Video.updateOne(
        { _id: videoId },
        { $push: { comments: { _id: id, email, comment, likes: [] } } }
      );
      res.status(200).send("commented successfully");
    } catch (error) {
      res.status(500).json({ message: "Error posting comment" });
    }
  });


  app.post('/upload', verifyUser, upload.single('video'), async (req, res, email) => {
    try {
      const { description } = req.body;
      const { email, author } = req.user;
      const inputUrl = req.file.path;

      const thumbnailPath = `./images/thumbnail.png`;

      ffmpeg(inputUrl)
        .screenshots({
          count: 1,
          filename: 'thumbnail.png',
          size: '320x240',
          folder: './images', // Specify the folder where you want to save the thumbnail
        })
        .on('end', () => {
          console.log('Thumbnail generated successfully!');

          // Upload the thumbnail to Cloudinary
          cloudinary.uploader.upload(thumbnailPath, { folder: 'thumbnails' }, async (error, thumbnailResult) => {
            if (error) {
              console.error(`Error uploading thumbnail to Cloudinary: ${error}`);
              res.status(500).send('Error uploading thumbnail to Cloudinary');
              return;
            }
            // upload the video to Cloudinary
            cloudinary.uploader.upload(inputUrl, { resource_type: 'video' }, async (videoError, videoResult) => {
              if (videoError) {
                console.error(`Error uploading video to Cloudinary: ${videoError}`);
                res.status(500).send('Error uploading video to Cloudinary');
                return;
              }

              const newVideo = new Video({
                email,
                description,
                author,
                videoUrl: videoResult.secure_url,
                thumbnailUrl: thumbnailResult.url,
              });

              // Save the video to the database
              const savedVideo = await newVideo.save();

              // Delete temporary files (video and thumbnail)
              fs.unlink(inputUrl, (err) => {
                if (err) {
                  console.error(`Error deleting video file: ${err}`);
                }
                console.log('Temporary video file deleted successfully');
              });

              fs.unlink(thumbnailPath, (err) => {
                if (err) {
                  console.error(`Error deleting thumbnail file: ${err}`);
                }
                console.log('Temporary thumbnail file deleted successfully');
              });

              // Update the corresponding user's posts array in the UserInfo schema
              await UserInfo.findOneAndUpdate(
                { email },
                { $push: { posts: savedVideo._id } }
              );

              res.status(201).json({ message: 'Video uploaded successfully' });
            });
          });
        })
        .on('error', (err) => {
          console.error('Error generating thumbnail:', err);
          res.status(500).json({ message: 'Error generating thumbnail' });
        });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Error uploading video' });
    }
  });

  app.post("/reels", verifyUser, async (req, res) => {
    try {
      // email of user
      const { email } = req.user;

      // Fetch all videos from the database
      const videos = await Video.find().sort({ createdAt: -1 });
      // Prepare the response with additional information

      const reelsWithInfo = await Promise.all(
        videos.map(async (video) => {
          const authorName = await getAuthorName(video.author);
          console.log(authorName);
          const profilePic = await getProfilePic(video._id);
          const likedStatus = await isVideoLikedByUser(video._id, email);
          const likesCount = video.likes.length;
          const commentsCount = video.comments.length;
          const savedStatus = await isVideoSavedByUser(video._id, email);
          // const savedByCount = await getSavedByCount(video._id); 

          return {
            ...video.toObject(),
            authorName,
            profilePic,
            likedStatus,
            likesCount,
            commentsCount,
            savedStatus,
            // savedByCount,
          };
        })
      );
      res.status(200).json(reelsWithInfo);
    } catch (error) {
      res.status(500).json({ error: "Internal server error", error });
      console.log(error)
    }
  });

  async function getAuthorName(authorId) {
    const login = await UserInfo.findOne({ authorId });
    return login ? login.name : "Unknown";
  }

  async function getProfilePic(authorId) {
    const person = await UserInfo.findById(authorId);
    return person ? person : null;
  }

  async function isVideoLikedByUser(videoId, email) {
    const video = await Video.findById(videoId);
    return video.likes.includes(email);
  }

  const getSavedByCount = async (videoId) => {
    const savedByCount = await getSavedByCountLogic(videoId);
    return savedByCount;
  }

  async function isVideoSavedByUser(videoId, email) {
    const video = await Video.findById(videoId);
    return video.saved.includes(email);
  }

  app.post("/message", async (req, res) => {
    try {
      const { from, to, message } = req.body;
      const newMessage = new Message({ from, to, message });
      await newMessage.save();
      res.status(200).json({ message: "Message sent successfully" });
    } catch (error) {
      res.status(500).json({ message: "Error sending message" });
    }
  });

  app.post("/retriveMessage", async (req, res) => {
    try {
      const { from, to } = req.body;
      const messages = await Message.find({
        $or: [
          { from: from, to: to },
          { from: to, to: from },
        ],
      });
      await Message.updateMany(
        {
          from: to,
          to: from,
        },
        {
          seen: true,
        }
      );
      // console.log(messages);
      res.status(200).json(messages);
    } catch (error) {
      res.status(500).json({ message: "Error retriving message" });
    }
  });

  app.post("/usersAndUnseenChatsAndLastMessage", async (req, res) => {
    try {
      const { email } = req.body;
      const pipeline = [
        {
          $match: {
            $or: [{ to: email }, { from: email }],
          },
        },
        {
          $sort: {
            _id: -1,
          },
        },
        {
          $group: {
            _id: {
              $cond: [{ $eq: ["$from", email] }, "$to", "$from"],
            },
            unseenCount: {
              $sum: {
                $cond: [{ $eq: ["$to", email] }, { $cond: ["$seen", 0, 1] }, 0],
              },
            },
            lastMessage: {
              $first: "$message",
            },
          },
        },
      ];

      const chattedUsers = await Message.aggregate(pipeline);

      // Get an array of unique user IDs from the chattedUsers result
      const emails = chattedUsers.map((user) => user._id);

      // Fetch the corresponding user details from the UserInfo collection
      const userNames = await UserInfo.find({ _id: { $in: emails } }, "name");

      // Create a map of email to userName for faster lookup
      const userNameMap = new Map();
      userNames.forEach((user) =>
        userNameMap.set(user._id.toString(), user.name)
      );

      // Merge the userName into the chattedUsers result
      const chattedUsersWithNames = chattedUsers.map((user) => {
        const person = UserInfo.findOne({ _id: user._id });
        return {
          _id: user._id,
          name: userNameMap.get(user._id.toString()) || "Deleted User",
          profilePic: person.profilePic,
          unseenCount: user.unseenCount,
          lastMessage: user.lastMessage,
        };
      });

      // console.log(chattedUsersWithNames);
      res.status(200).json(chattedUsersWithNames);
    } catch (error) {
      res.status(500).json({ message: "Error retriving Last chat & info" });
    }
  });

  app.post("/getPostsAndSaved", async (req, res) => { // !
    try {
      const { email, reqId } = req.body;
      const Info = await UserInfo.findOne({ _id: email });
      const posts = Info.posts;
      const saved = Info.saved;
      const followers = Info.followers;
      const following = Info.following;

      const postsInfo = await Promise.all(
        posts.map(async (post) => {
          const video = await Video.findById(post);
          return video;
        })
      );

      const savedInfo = await Promise.all(
        saved.map(async (save) => {
          const video = await Video.findById(save);
          return video;
        })
      );

      const followersInfo = await Promise.all(
        followers.map(async (follower) => {
          const user = await UserInfo.findById(follower);
          return {
            followerId: follower,
            followerName: user.fancyId,
            followerPic: user.profilePic,
            following: user.followers.includes(reqId),
          };
        })
      );

      const followingInfo = await Promise.all(
        following.map(async (follow) => {
          const user = await UserInfo.findById(follow);
          return {
            followingId: follow,
            followingName: user.fancyId,
            followingPic: user.profilePic,
            following: user.followers.includes(reqId),
          };
        })
      );

      res.status(200).json({ postsInfo, savedInfo, followersInfo, followingInfo });
    } catch (error) {
      res.status(500).json({ message: "Error retriving Last chat & info" });
      console.log(error);
    }
  });

  app.post("/getTokens", async (req, res) => {
    try {
      const { _id } = req.body;
      const getToken = await UserInfo.findOne({ _id });
      if (getToken) {
        res.status(200).json(getToken["tokens"]);
      } else {
        res.status(404).json({ message: "Tokens not found" });
      }
    } catch (error) {
      res.status(500).json({ message: "Error retreiving Tokens" });
    }
  });

  app.post("/updateTokens", async (req, res) => {
    try {
      const { _id, tokens } = req.body;
      const updateToken = await UserInfo.updateOne({ _id }, { $inc: { tokens } });
      if (updateToken) {
        res.status(200).json({ message: "Tokens updated successfully" });
      } else {
        res.status(404).json({ message: "Tokens not updated" });
      }
    } catch (error) {
      res.status(500).json({ message: "Error updating Tokens" });
    }
  });

  app.post("/storeInterests", async (req, res) => {
    try {
      const { _id, interests } = req.body;
      const addInterests = await UserInfo.updateOne({ _id }, { interests });
      if (addInterests) {
        res.status(200).json({ message: "Interests updated successfully" });
      } else {
        res.status(404).json({ message: "Interests not updated" });
      }
    } catch (error) {
      res.status(500).json({ message: "Error updating Interests" });
    }
  });

  app.post("/getInterests", async (req, res) => {
    try {
      const { _id } = req.body;
      const getInterests = await UserInfo.findOne({ _id });
      if (getInterests) {
        res.status(200).json(getInterests["interests"]);
      } else {
        res.status(404).json({ message: "Interests not found" });
      }
    } catch (error) {
      res.status(500).json({ message: "Error retreiving Interests" });
    }
  });

  app.post("/like", async (req, res) => {
    try {
      const { videoId, email, likedStatus } = req.body;

      // Check if the video exists
      const video = await Video.findById(videoId);

      if (!video) {
        return res.status(404).json({ message: "Video not found" });
      }

      // Check if the user has already liked the video
      const userAlreadyLiked = video.likes.includes(email);

      // Perform like/dislike action based on likedStatus
      if (likedStatus && !userAlreadyLiked) {

        video.likes.push(email);
      } else if (likedStatus && userAlreadyLiked) {

        video.likes = video.likes.filter(id => id !== email);
      }

      // Save the updated video
      await video.save();

      res.status(200).json({ message: "Video liked/disliked successfully" });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Error liking/disliking video" });
    }
  });

  app.post("/save", async (req, res) => {
    try {
      const { videoId, email, savedStatus } = req.body;
      if (savedStatus) {
        await Video.updateOne({ _id: videoId }, { $pull: { saved: email } });
        await UserInfo.updateOne({ _id: email }, { $pull: { saved: videoId } });
      } else {
        await Video.updateOne({ _id: videoId }, { $push: { saved: email } });
        await UserInfo.updateOne({ _id: email }, { $push: { saved: videoId } });
      }

      res.status(200).json({ message: "Video saved/unsaved successfully" });
    } catch (error) {
      res.status(500).json({ message: "Error saving/unsaving video" });
    }
  });

  app.post("/likeComment", async (req, res) => {
    try {
      const { videoId, commentId, email, likedStatus } = req.body;
      if (likedStatus) {
        await Video.updateOne(
          { _id: videoId, "comments._id": new ObjectId(commentId) },
          { $pull: { "comments.$.likes": email } }
        );
      } else {
        await Video.updateOne(
          { _id: videoId, "comments._id": new ObjectId(commentId) },
          { $push: { "comments.$.likes": email } }
        );
      }
      res.status(200).json({ message: "Comment liked/disliked successfully" });
    } catch (error) {
      res.status(500).json({ message: "Error liking/disliking comment" });
    }
  });

  app.post("/getComments", async (req, res) => {
    try {
      const { videoId, email } = req.body;
      const video = await Video.findById(videoId);
      const comments = video.comments;
      const commentsWithInfo = await Promise.all(
        comments.map(async (comment) => {
          const authorName = await getAuthorName(comment.author);
          const profilePic = await getProfilePic(comment.author);
          const likedStatus = await comment.likes.includes(email);
          const likesCount = comment.likes.length;
          return {
            ...comment,
            authorName,
            profilePic,
            likedStatus,
            likesCount,
          };
        })
      );
      res.status(200).json(commentsWithInfo);
    } catch (error) {
      res.status(500).json({ message: "Error retrieving comments" });
    }
  });


  app.post("/deleteComment", verifyUser, async (req, res) => {
    try {
      const { videoId, commentId } = req.body;
      const { email } = req.user;

      // Check if the video exists
      const video = await Video.findOne({ _id: videoId });
      if (!video) {
        return res.status(404).json({ message: "Video not found" });
      }

      // Find the comment by its ID
      const commentToDelete = video.comments.find(comment => comment._id.toString() === commentId);

      // Check if the comment existsz
      if (!commentToDelete) {
        return res.status(404).json({ message: "Comment not found" });
      }

      if (commentToDelete.email !== email) {
        return res.status(403).json({ message: "You are not authorized to delete this comment" });
      }

      // Remove the comment from the comments array
      video.comments = video.comments.filter(comment => comment._id.toString() !== commentId);

      // Save the updated video
      await video.save();

      res.status(200).json({ message: "Comment deleted successfully" });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Error deleting comment" });
    }
  });

  function matchSockets(socket) {
    if (availableUsers.size < 2) {
      socket.emit("chatError", "Waiting for another user to join...");
      return;
    }

    const myInterests = availableUsers.get(socket.id);

    // Remove the current user from the available users map
    availableUsers.delete(socket.id);

    // Find a matching user
    const match = [...availableUsers.entries()].find(([_, interests]) => {
      return interests.some((interest) => myInterests.includes(interest));
    });

    if (!match) {
      // No user with similar interests found, recursively call matchSockets again
      matchSockets(socket);
      return;
    }

    const [otherSocketId, otherUserInterests] = match;

    // Remove the selected user from the available users map
    availableUsers.delete(otherSocketId);

    // Create a chat room or session
    const roomId = uuid.v4();

    // Store the room ID in the sockets' custom properties for later use
    socket.data.roomId = roomId;
    const otherSocket = io.sockets.sockets.get(otherSocketId);
    otherSocket.data.roomId = roomId;

    socket.join(roomId);
    otherSocket.join(roomId);

    // Notify the users about the match and the room ID
    socket.emit("chatMatched", {
      roomId: roomId,
      to: otherSocketId,
    });
  }

  // Store the active connections
  const availableUsers = new Map();

  // Handle socket.io connections
  io.on("connection", (socket) => {
    socket.emit("create", socket.id);
    console.log(`${socket.id} connected`);

    // Store the user's socket connection
    socket.on("reConnect", (interests) => {
      // console.log(interests.data);
      availableUsers.set(socket.id, interests.data);
    });

    socket.on("startChat", () => {
      matchSockets(socket);
    });

    // Handle offer signaling
    socket.on("call-user", (data) => {
      const { offer, targetSocketID } = JSON.parse(data);
      io.to(targetSocketID).emit("call-made", {
        sourceSocketID: socket.id,
        offer: offer,
      });
    });

    // Handle answer signaling
    socket.on("make-answer", (data) => {
      console.log("make-answer");
      const { answer, targetSocketID } = JSON.parse(data);
      io.to(targetSocketID).emit("answer-made", {
        sourceSocketID: socket.id,
        answer: answer,
      });
    });

    // Handle ICE candidate signaling
    socket.on("ice-candidate", (data) => {
      console.log("ice-candidate");
      const { targetSocketID, candidate } = JSON.parse(data);
      io.to(targetSocketID).emit("ice-candidate", {
        sourceSocketID: socket.id,
        candidate: candidate,
      });
    });

    socket.on("message", (data) => {
      const roomId = socket.data.roomId;
      socket.to(roomId).emit("message", data);
    });

    socket.on("ask-increment", () => {
      const roomId = socket.data.roomId;
      socket.to(roomId).emit("ask-increment");
    });

    socket.on("reply-increment", (data) => {
      const roomId = socket.data.roomId;
      socket.to(roomId).emit("reply-increment", data);
    });

    socket.on("ask-chat", (data) => {
      const roomId = socket.data.roomId;
      const allData = JSON.parse(data);
      socket.to(roomId).emit("ask-chat", allData);
    });

    socket.on("reply-chat", (data) => {
      const roomId = socket.data.roomId;
      const allData = JSON.parse(data);
      socket.to(roomId).emit("reply-chat", allData);
    });

    socket.on("close-chat", () => {
      const roomId = socket.data.roomId;
      socket.to(roomId).emit("close-chat");
    });

    socket.on("ask-exchange-numbers", () => {
      const roomId = socket.data.roomId;
      socket.to(roomId).emit("ask-exchange-numbers");
    });
    socket.on("reply-exchange-numbers", (data) => {
      const roomId = socket.data.roomId;
      socket.to(roomId).emit("reply-exchange-numbers", data);
    });

    // Handle disconnection
    socket.on("disconnect", () => {
      availableUsers.delete(socket.id);
      const roomId = socket.data.roomId;
      if (roomId) {
        socket.to(roomId).emit("hangup");
        // Clean up the room data
        socket.leave(roomId);
        delete socket.data.roomId;
      }
      console.log(`${socket.id} disconnected`);
    });
  });

  // forgotPassword
  app.post("/verify-email", async (req, res) => {
    const { email } = req.body;
    const existingUser = await UserInfo.findOne({ email });
    if (existingUser) {
      res.status(200).json({ message: true });
      return;
    }
    res.status(404).json({ message: false });
  });

  app.post("/change-password", async (req, res) => {
    try {
      const { email, password } = req.body;
      const updatePassword = await UserInfo.updateOne({ email }, { password });
      if (updatePassword) {
        res.status(200).json({ message: "Password changed successfully" });
      } else {
        res.status(404).json({ message: "Password not changed" });
      }
    } catch (error) {
      res.status(500).json({ message: "Error changing Password" });
    }
  });

  // Create a transporter using Gmail SMTP configuration
  const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    auth: {
      user: process.env.EMAIL,
      pass: process.env.APP_PASSWORD,
    },
  });

  // Handle POST request to verify email and send OTP
  app.post("/send-email", (req, res) => {
    const { email } = req.body;

    // Generate OTP
    const otp = otpGenerator.generate(4, {
      digits: true,
      alphabets: false,
      upperCase: false,
      specialChars: false,
    });

    // Compose the email message
    const mailOptions = {
      from: `NetTeam Support <${process.env.EMAIL}>`,
      to: email,
      subject: "Email Verification",
      text: `Your OTP is: ${otp}`,
    };

    // Send the email
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.log("Error:", error);
        res
          .status(500)
          .json({ error: "An error occurred while sending the email" });
      } else {
        console.log("Email sent:", info.response);
        res.status(200).json(otp);
      }
    });
  });

  // PayPal configuration
  paypal.configure({
    mode: "sandbox", // Set 'live' for production mode
    client_id: process.env.PAYPAL_CLIENT_ID,
    client_secret: process.env.PAYPAL_CLIENT_SECRET,
  });

  // Payment endpoint
  app.post("/payment", (req, res) => {
    const paymentAmount = req.body.amount; // Amount received from frontend

    const create_payment_json = {
      intent: "sale",
      payer: {
        payment_method: "paypal",
      },
      transactions: [
        {
          amount: {
            total: paymentAmount.toFixed(2),
            currency: "USD",
          },
        },
      ],
      redirect_urls: {
        return_url: process.env.PAYPAL_RETURN_URL,
        cancel_url: process.env.PAYPAL_CANCEL_URL,
      },
    };

    paypal.payment.create(create_payment_json, (error, payment) => {
      if (error) {
        res
          .status(500)
          .json({ status: "error", message: "Payment creation failed" });
      } else {
        for (let i = 0; i < payment.links.length; i++) {
          if (payment.links[i].rel === "approval_url") {
            res.json({ status: "created", approvalUrl: payment.links[i].href });
          }
        }
      }
    });
  });

  // Payment confirmation endpoint
  app.get("/payment/confirm", (req, res) => {
    const payerId = req.query.PayerID;
    const paymentId = req.query.paymentId;

    const execute_payment_json = {
      payer_id: payerId,
    };

    paypal.payment.execute(paymentId, execute_payment_json, (error, payment) => {
      if (error) {
        res
          .status(500)
          .json({ status: "error", message: "Payment execution failed" });
      } else {
        res.json({ status: "success", message: "Payment successful" });
      }
    });
  });
  // Supercht end

  app.post("/updateName", async (req, res) => {
    try {
      const { _id, name } = req.body;
      await UserInfo.updateOne({ _id }, { name });
      res.status(200).json({ message: "Name updated successfully" });
    } catch (error) {
      res.status(500).json({ message: "Error updating Name" });
    }
  });

  app.post("/updateFancyId", async (req, res) => {
    try {
      const { _id, fancyId } = req.body;
      await UserInfo.updateOne({ _id }, { fancyId });
      res.status(200).json({ message: "FancyId updated successfully" });
    } catch (error) {
      res.status(500).json({ message: "Error updating FancyId" });
    }
  });

  app.post("/updateEmail", async (req, res) => {
    try {
      const { _id, email } = req.body;
      await UserInfo.updateOne({ _id }, { email });
      res.status(200).json({ message: "Email updated successfully" });
    } catch (error) {
      res.status(500).json({ message: "Error updating Email" });
    }
  });

  app.post("/updateSocial", async (req, res) => {
    try {
      const { _id, socialId } = req.body;
      await UserInfo.updateOne({ _id }, { socialId });
      res.status(200).json({ message: "Email updated successfully" });
    } catch (error) {
      res.status(500).json({ message: "Error updating Email" });
    }
  });

  app.post("/getAllUsers", async (req, res) => {
    try {
      const { _id } = req.body;
      const users = await UserInfo.find({ _id: { $ne: _id } });
      const updatedUsers = users.map((user) => ({
        ...user._doc,
        following: user.followers.includes(_id),
      }));
      res.status(200).json(updatedUsers);
    } catch (error) {
      res.status(500).json({ message: "Error getting all users" });
    }
  });

  app.post("/getUserProfile", async (req, res) => {
    try {
      const { _id, reqId } = req.body;
      const user = await UserInfo.find({ _id });
      const updatedUser = {
        ...user[0]._doc,
        following: user[0].followers.includes(reqId),
      };
      res.status(200).json(updatedUser);
    } catch (error) {
      res.status(500).json({ message: "Error getting all users" });
    }
  });

  app.post("/follow", verifyUser, async (req, res) => {
    try {
      const { _id, reqId, followStatus } = req.body;
      if (followStatus) {
        await UserInfo.updateOne({ _id }, { $pull: { followers: reqId } });
        await UserInfo.updateOne({ _id: reqId }, { $pull: { following: _id } });
      } else {
        await UserInfo.updateOne({ _id }, { $push: { followers: reqId } });
        await UserInfo.updateOne({ _id: reqId }, { $push: { following: _id } });
      }
      res.status(200).json({ message: "Person followed/unfollowed successfully" });
    } catch (error) {
      res.status(500).json({ message: "Error followed/unfollowed Person" });
    }

  });

  app.listen(port, () => {
    console.log(`this server is running on ${port}`);

  })
};

const initializeApp = async () => {
  await connectToMongo();
  await startServer();
}

initializeApp();
