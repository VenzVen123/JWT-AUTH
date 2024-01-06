import { request } from "express";
import Users from "../models/UserModel.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

export const getUsers = async (req, res) => {
  try {
    const users = await Users.findAll({
        attributes:['id','name','email']
    });
    res.json(users);
  } catch (error) {
    console.error(error);
    res.status(500).json({ msg: "Internal Server Error" });
  }
};

export const Register = async (req, res) => {
  const { name, email, password, confirmPassword } = req.body;
  if (password !== confirmPassword) {
    return res.status(400).json({ msg: "Password dan confirm pass not cocok" });
  }

  try {
    const salt = await bcrypt.genSalt();
    const hashPassword = await bcrypt.hash(password, salt);

    await Users.create({
      name: name,
      email: email,
      password: hashPassword,
    });

    res.json({ msg: "Register done" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ msg: "Internal Server Error" });
  }
};

export const Login = async (req, res) => {
  try {
    const user = await Users.findOne({
      where: {
        email: req.body.email,
      },
    });

    if (!user) {
      return res.status(404).json({ msg: "Email not found" });
    }

    const match = await bcrypt.compare(req.body.password, user.password);

    if (!match) {
      return res.status(400).json({ msg: "Invalid password" });
    }

    const { id, name, email } = user;

    const accessToken = jwt.sign(
      { userId: id, name, email },
      process.env.ACCESS_TOKEN_SECRET,
      {
        expiresIn: '20s',
      }
    );

    const refreshToken = jwt.sign(
      { userId: id, name, email },
      process.env.REFRESH_TOKEN_SECRET,
      {
        expiresIn: '1d',
      }
    );

    // Update the user with the new refresh token
    await Users.update({ refresh_token: refreshToken }, {
      where: {
        id: user.id,
      },
    });

    // Set the refreshToken as an HttpOnly cookie with a secure flag
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000,
      secure: process.env.NODE_ENV === 'production', // Set to true in production
    });

    res.json({ accessToken });
  } catch (error) {
    console.error(error);
    res.status(500).json({ msg: "Internal Server Error" });
  }
};

export const Logout = async(req,res)=>{
    const refreshToken = req.cookies.refreshToken;
    if(!refreshToken) return res.sendStatus(204);
    const user = await Users.findAll({
        where:{
            refresh_token : refreshToken
        }
    });
    if (!user[0]) return res.sendStatus(204);
    const userId = user[0].id ;
    await Users.update({refresh_token: null},{
        where:{
            id : userId
        }
    });
    res.clearCokkie(refreshToken);
    return res.sendStatus(200); 
}