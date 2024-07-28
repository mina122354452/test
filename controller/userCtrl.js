const expressAsyncHandler = require("express-async-handler");
const User = require("../models/userModel");
const jwt = require("jsonwebtoken");
const sendEmail = require("./emailCtrl");
const crypto = require("crypto");
const { generateToken } = require("../config/jwt");
const { generateRefreshToken } = require("../config/refreshToken");
const {
  generatePasswordResetMail,
  generateVerifyMail,
} = require("../messages/email");
const validateMongoDbId = require("../utils/validateMongodbId");
const Service = require("../models/serviceModel");
const createUser = expressAsyncHandler(async (req, res) => {
  const { firstname, lastname, email, password } = req.body;
  const findUser = await User.findOne({ email });
  if (!findUser) {
    const newUser = await User.create({
      firstname,
      lastname,
      email,

      password,
    });
    if (newUser.emailConfirm === false) {
      verifyEmailToken(req, res);
    } else {
      return res.status(201).json({
        message: "User created",
      });
    }
  } else {
    if (findUser.emailConfirm === false) {
      verifyEmailToken(req, res);
    } else {
      //FIXME:cutsom error handler
      throw new Error("user is already exist");
    }
  }
});
const loginUser = expressAsyncHandler(async (req, res) => {
  const { email, password } = req.body;
  const findUser = await User.findOne({ email });
  if (!findUser) {
    throw new Error("there isn't exist user");
  }
  const passwordStatus = await findUser.isPasswordMatched(password);

  if (findUser && passwordStatus) {
    const mobile = findUser.mobile;
    if (findUser.emailConfirm === false) {
      verifyEmailToken(req, res);
    } else if (findUser.isBlocked == true) {
      throw new Error("User is blocked");
    } else {
      const refreshToken = await generateRefreshToken(findUser?.id);
      const updateUser = await User.findByIdAndUpdate(
        findUser?._id,
        {
          refreshToken: refreshToken,
        },
        {
          new: true,
        }
      );
      res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        sameSite: "strict",
        secure: true,
        maxAge: 72 * 60 * 60 * 1000, // 3 days
      });
      res.status(200).json({
        id: findUser?._id,
        firstname: findUser?.firstName,
        lastname: findUser?.lastName,
        email: findUser?.email,
        mobile: findUser?.mobile,
        token: generateToken(findUser?._id),
      });
    }
  } else {
    //FIXME:cutsom error handler
    throw new Error("Invalid credentials");
  }
});
const verifyEmailToken = expressAsyncHandler(async (req, res) => {
  const { email } = req.body;
  console.log(req.body);

  const user = await User.findOne({ email });

  if (!user) throw new Error("User Not Found With this email");
  try {
    if (user.emailConfirm === false) {
      const token = await user.verifyEmail();
      await user.save();
      // todo
      let mail = await generateVerifyMail(token, user.firstname, user.lastname);
      console.log(token);
      const data = {
        to: email,
        subject: "verify your Email",
        html: mail,
      };
      await sendEmail(data);
      res.status(201).json({
        status: "successfully",
        message: "we sent email verification",
      });
    } else {
      res.status(100).json({
        status: "Not Modified",
        message: "your email is already verified",
      });
    }
  } catch (error) {
    throw new Error(error);
  }
});
const verifyEmail = expressAsyncHandler(async (req, res) => {
  const { token } = req.params;
  const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
  const user = await User.findOne({
    emailVerify: hashedToken,
    emailVerifyExpires: {
      $gt: Date.now(),
    },
  });
  //FIXME:cutsom error handler
  if (!user) throw new Error("token Expired,please try again later");
  user.emailConfirm = true;
  user.emailVerify = undefined;
  user.emailVerifyExpires = undefined;
  await user.save();
  if (user.emailConfirm === true) {
    res.status(202).json({
      status: "successfully",
      message: "user created and verified successfully",
    });
  }
});
const loginAdmin = expressAsyncHandler(async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) throw Error("no credentials");

  const findAdmin = await User.findOne({ email });
  if (findAdmin.role !== "admin") throw new Error("Not Authorized");
  const passwordStatus = await findAdmin.isPasswordMatched(password);
  if (findAdmin && passwordStatus) {
    const refreshToken = await generateRefreshToken(findAdmin?.id);
    const updateUser = await User.findByIdAndUpdate(
      findAdmin?._id,
      {
        refreshToken: refreshToken,
      },
      {
        new: true,
      }
    );
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      sameSite: "strict",
      secure: true,
      maxAge: 72 * 60 * 60 * 1000,
    });
    res.status(200).json({
      id: findAdmin?._id,
      firstname: findAdmin?.firstName,
      lastname: findAdmin?.lastName,
      email: findAdmin?.email,
      mobile: findAdmin?.mobile,
      token: generateToken(findAdmin?._id),
    });
  } else {
    throw new Error("Invalid credentials");
  }
});
const handleRefreshToken = expressAsyncHandler(async (req, res) => {
  let cookie = await req.cookies;

  if (!cookie?.refreshToken) {
    //FIXME:cutsom error handler

    throw new Error("No refresh token in cookies");
  }
  const refreshToken = cookie.refreshToken;

  const user = await User.findOne({
    refreshToken,
  });
  if (!user) throw new Error("No refresh token in db or matched");
  jwt.verify(refreshToken, process.env.JWT_SECRET, (err, decoded) => {
    if (err || user.id !== decoded.id) {
      throw new Error("Refresh token is not valid");
    }
    const accessToken = generateToken(user?._id);
    res.status(200).json({ accessToken });
  });
});

const logout = expressAsyncHandler(async (req, res) => {
  const cookie = req.cookies;
  if (!cookie?.refreshToken) {
    //FIXME:cutsom error handler

    throw new Error("No refresh token in cookies");
  }
  const refreshToken = cookie.refreshToken;
  const user = await User.findOne({
    refreshToken,
  });
  if (!user) {
    res.clearCookie("refreshToken", {
      httpOnly: true,

      secure: true,
    });
    return res.sendStatus(204);
  }
  await User.findOneAndUpdate(
    { refreshToken },
    {
      refreshToken: "",
    }
  );
  res.clearCookie("refreshToken", {
    httpOnly: true,
    secure: true,
  });
  return res.sendStatus(204);
});

const getallUser = expressAsyncHandler(async (req, res) => {
  try {
    // Filtering
    const queryObj = { ...req.query };
    const excludeFields = ["page", "sort", "limit", "fields"];
    excludeFields.forEach((el) => delete queryObj[el]);

    // Advanced filtering for comparison operators
    let queryStr = JSON.stringify(queryObj);

    // Parse the modified query string back into an object
    const parsedQueryObj = JSON.parse(queryStr);

    // Add regex search for title or any other text fields
    if (parsedQueryObj.firstname) {
      parsedQueryObj.firstname = {
        $regex: parsedQueryObj.firstname,
        $options: "i",
      };
    }
    if (parsedQueryObj.lastname) {
      parsedQueryObj.lastname = {
        $regex: parsedQueryObj.lastname,
        $options: "i",
      };
    }

    let query = User.find(parsedQueryObj);

    // Find the product with the minimum price

    // If there are no matching products, return appropriate response

    // Sorting
    if (req.query.sort) {
      const sortBy = req.query.sort.split(",").join(" ");
      query = query.sort(sortBy);
    } else {
      query = query.sort("-createdAt");
    }

    // Limiting the fields
    if (req.query.fields) {
      const fields = req.query.fields.split(",").join(" ");
      query = query.select(fields);
    } else {
      query = query.select(
        "-emailVerifyExpires -emailVerify -emailConfirm   -__v"
      );
    }

    // Pagination
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    query = query.skip((page - 1) * limit).limit(limit);

    // Count total number of documents for pagination
    const totalProducts = await User.countDocuments(parsedQueryObj);

    // Calculate total pages
    const totalPages = Math.ceil(totalProducts / limit);

    if (req.query.page && page > totalPages) {
      return res.status(404).json({
        message: "This page does not exist",
      });
    }

    const user = await query;

    // Include only the prices of the min and max products in the response
    res.json({
      user,
      totalPages,
    });
  } catch (error) {
    console.log(error);
    res.status(400).send({ message: error.message });
  }
});
const getaUser = expressAsyncHandler(async (req, res) => {
  const { id } = req.params;
  validateMongoDbId(id);

  try {
    const getaUser = await User.findById(id);
    res.status(200).json({ getaUser });
  } catch (err) {
    //FIXME:cutsom error handler

    throw new Error(err);
  }
});
const getUserDetails = expressAsyncHandler(async (req, res) => {
  const { id } = req.user;
  validateMongoDbId(id);

  try {
    const getaUser = await User.findById(id).select(
      "firstname lastname email mobile address isSeller -_id"
    );
    res.status(200).json({ getaUser });
  } catch (err) {
    //FIXME:cutsom error handler

    throw new Error(err);
  }
});

const updateUser = expressAsyncHandler(async (req, res) => {
  const { id } = req.user;
  validateMongoDbId(id);
  try {
    const user = await User.findById(id);

    if (req?.body?.firstName) user.firstname = req?.body?.firstName;
    if (req?.body?.lastName) user.lastname = req?.body?.lastName;
    if (req?.body?.email) user.email = req?.body?.email;
    if (req?.body?.mobile) user.mobile = req?.body?.mobile;
    user.save();
    res.status(202).json({ status: "success", message: "updated user data" });
  } catch (error) {
    //FIXME:cutsom error handler

    throw new Error(error);
  }
});

const deleteaUser = expressAsyncHandler(async (req, res) => {
  const { id } = req.params;
  validateMongoDbId(id);

  try {
    const deleteaUser = await User.findByIdAndDelete(id);
    res.status(200).json({
      status: "success",
      message: "User Deleted successfully",
    });
  } catch (err) {
    //FIXME:cutsom error handler

    throw new Error(err);
  }
});

const blockUser = expressAsyncHandler(async (req, res) => {
  const { id } = req.params;
  validateMongoDbId(id);

  try {
    const block = await User.findByIdAndUpdate(
      id,
      {
        isBlocked: true,
      },
      {
        new: true,
      }
    );
    res.status(202).json({ status: "success", message: "User Blocked" });
  } catch (err) {
    //FIXME:cutsom error handler

    throw new Error(err);
  }
});
const unblockUser = expressAsyncHandler(async (req, res) => {
  const { id } = req.params;
  validateMongoDbId(id);

  try {
    const block = await User.findByIdAndUpdate(
      id,
      {
        isBlocked: false,
      },
      {
        new: true,
      }
    );
    res.status(202).json({ status: "success", message: "User unBlocked" });
  } catch (err) {
    //FIXME:cutsom error handler

    throw new Error(err);
  }
});
const updatePassword = expressAsyncHandler(async (req, res) => {
  const { _id } = req.user;
  const { password } = req.body;
  validateMongoDbId(_id);
  const user = await User.findById(_id);
  if (password) {
    user.password = password;
    user.passwordChangedAt = Date.now();
    const updatedPassword = await user.save();
    res
      .status(200)
      .json({ status: "success", message: "password updated successfully" });
  } else {
    res.json(user);
  }
});
const forgotPasswordToken = expressAsyncHandler(async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) throw new Error("User Not Found With this email");
  try {
    const token = await user.createPasswordResetToken();
    await user.save();
    // todo
    let mail = await generatePasswordResetMail(
      token,
      user.firstname,
      user.lastname
    );
    console.log(token);
    const data = {
      to: email,
      subject: "Reset Password link",
      html: mail,
    };
    await sendEmail(data);

    res.status(200).json({
      status: "success",
      message: "Password reset token sent to your email",
    });
  } catch (error) {
    //FIXME:cutsom error handler
    throw new Error(error);
  }
});

const resetPassword = expressAsyncHandler(async (req, res) => {
  const { password } = req.body;
  const { token } = req.params;
  const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: {
      $gt: Date.now(),
    },
  });
  if (!user) throw new Error("token Expired,please try again later");
  user.password = password;
  user.passwordChangedAt = Date.now();
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  await user.save();
  res.json({
    status: "success",
    message: "password changed successfully",
  });
});
//! working -- logic not complete
//!need hard test
const becomeServant = expressAsyncHandler(async (req, res) => {
  const { id } = req.params;
  const { serviceId } = req.body;
  validateMongoDbId(id);
  const user = await User.findById(id);
  if (!serviceId && !req.user.mainService) {
    if (req.user.role == "admin" || req.user.SecretaryGeneralOfServices) {
      throw new Error("you didn't provide any service id");
    } else if (
      req.user.role == "user" &&
      !req.user.SecretaryGeneralOfServices &&
      !req.user.mainService
    ) {
      throw new Error(
        "you don't serve in certain service and you aren't admin or Secretary General Of Services"
      );
    }
  } else {
    if (req.user.role == "admin" || req.user.SecretaryGeneralOfServices) {
      const service = await Service.findById(serviceId);
      if (!service) {
        throw new Error("there aren't any services with this id");
      } else {
        if (
          user.servesIn.includes(serviceId) &&
          service.servants.includes(id)
        ) {
          throw new Error("this user already serves in this service");
        }
        if (!user.servesIn.includes(serviceId)) {
          user.servesIn.push(serviceId);
        }

        if (!service.servants.includes(id)) {
          service.servants.push(id);
        }
        service.save();
      }
    } else {
      const service = await Service.findById(req.user.mainService);
      if (!service) {
        throw new Error("there aren't any services with this id");
      } else {
        if (
          user.servesIn.includes(req.user.mainService) &&
          service.servants.includes(id)
        ) {
          throw new Error("this user already serves in this service");
        }
        if (!user.servesIn.includes(req.user.mainService)) {
          user.servesIn.push(req.user.mainService);
        }

        if (!service.servants.includes(id)) {
          service.servants.push(id);
        }

        service.save();
      }
    }
  }

  user.servant = true;
  user.save();
  res.json({
    status: "success",
    message: `user now is servant successfully`,
  });
});
const unBecomeServant = expressAsyncHandler(async (req, res) => {
  const { id } = req.params;
  const { serviceId } = req.body;
  validateMongoDbId(id);
  const user = await User.findById(id);
  if (!serviceId && !req.user.mainService) {
    if (req.user.role == "admin" || req.user.SecretaryGeneralOfServices) {
      throw new Error("you didn't provide any service id");
    } else if (
      req.user.role == "user" &&
      !req.user.SecretaryGeneralOfServices &&
      !req.user.mainService
    ) {
      throw new Error(
        "you don't serve in certain service and you aren't admin or Secretary General Of Services"
      );
    }
  } else {
    if (req.user.role == "admin" || req.user.SecretaryGeneralOfServices) {
      const service = await Service.findById(serviceId);
      if (!service) {
        throw new Error("there aren't any services with this id");
      } else {
        if (
          !user.servesIn.includes(serviceId) &&
          !service.servants.includes(id)
        ) {
          throw new Error("this user don't serve in this service");
        }

        if (user.servesIn.includes(serviceId)) {
          user.servesIn = user.servesIn.filter(
            (serviceid) => !serviceid.equals(serviceId)
          );
        }

        if (service.servants.includes(id)) {
          service.servants = service.servants.filter(
            (servantId) => !servantId.equals(id)
          );
        }

        await service.save();
      }
    } else {
      const service = await Service.findById(req.user.mainService);
      if (!service) {
        throw new Error("there aren't any services with this id");
      } else {
        if (
          !user.servesIn.includes(req.user.mainService) &&
          !service.servants.includes(id)
        ) {
          throw new Error("you don't serve in this service");
        }

        if (user.servesIn.includes(req.user.mainService)) {
          user.servesIn = user.servesIn.filter(
            (serviceid) => !serviceid.equals(req.user.mainService)
          );
        }

        if (service.servants.includes(id)) {
          service.servants = service.servants.filter(
            (servantId) => !servantId.equals(id)
          );
        }

        await service.save();
      }
    }
  }

  user.servant = false;

  user.save();
  res.json({
    status: "success",
    message: "user now isn't servant ",
  });
});
module.exports = {
  createUser,
  verifyEmailToken,
  verifyEmail,
  loginUser,
  loginAdmin,
  handleRefreshToken,
  logout,
  getallUser,
  getaUser,
  getUserDetails,
  updateUser,
  deleteaUser,
  blockUser,
  unblockUser,
  updatePassword,
  forgotPasswordToken,
  resetPassword,
  becomeServant,
  unBecomeServant,
};
