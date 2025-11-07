import dotenv from "dotenv";
dotenv.config();
import { PrismaClient, type Todo } from "./generated/prisma/client.js";
import express, { type NextFunction, type Request, type Response } from "express";
import z, { email } from "zod";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { title } from "process";
const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT;
const SALTROUNDS = 10;
const SECRET_PASSWORD = process.env.SECRET_PASSWORD!;
app.use(express.json()); // To obtain the body of the request coming

interface Decode  {
    id: number;
}
const auth = (req: Request,res: Response,next: NextFunction) => {
    const authHeader = req.headers['authorization'];
    if(!authHeader){
        return res.json({
            message: "Bearer token is not present"
        })
    }
    const token = authHeader.split(' ')[1]!;
    if(!token){
        return res.status(HTTPStatusCode.InvalidInput).json({
            message: "Token not present"
        })
    }
    try{
        const decode = jwt.verify(token, SECRET_PASSWORD) as Decode;
        (req as any)["userid"] = decode.id;
        next();
    }catch(err){
        return res.status(HTTPStatusCode.OK).json({
            message: "invalid or expired token"
        })
    }
}

enum HTTPStatusCode {
    SomethingWentWrong = 404,
    InvalidInput = 411,
    InternalServerError = 500,
    OK = 200
}

const SignupParams = z.object({
  username: z.string().min(1,{message: "Username should not be empty"}),
  firstName: z.string().min(1, {message: "Firstname could not be empty"}),
  lastName: z.string().min(1, {message: "Lastname could not be empty"}),
  password: z.string().min(8,{message: "Password should hhave the min length of 8 characters"}).max(15,{message: "Password should have the max length of 15 characters"}),
  email: z.email({message: "Invalid email format"})
});

type SignupType = z.infer<typeof SignupParams>;

const TodoParams = z.object({
    id: z.number().optional(),
    title: z.string().min(1, {message: "Title cannot be empty"}).optional(),
    description: z.string().min(1, {message: "Description cannot be empty"}).optional(),
    done: z.boolean().optional(),
})

type TodoType = z.infer<typeof TodoParams>

app.post("/signup", async (req,res) => {
    try{
        const parsedInput = SignupParams.safeParse(req.body);
        if(!parsedInput.success){
            return res.status(HTTPStatusCode.InvalidInput).json({
                message: "Cannot parse the input data"
            })
        }
        const username = parsedInput.data.username;
        const firstName = parsedInput.data.firstName;
        const lastName = parsedInput.data.lastName;
        const email = parsedInput.data.email;
        const password = parsedInput.data.password;

        const response = await prisma.user.findFirst({
            where: {
                username
            }
        })

        if(response){
            return res.status(HTTPStatusCode.SomethingWentWrong).json({
                message: "User already exists"
            })
        }

        const hashedPassword = await bcrypt.hash(password,SALTROUNDS);
        
        const newUser = await prisma.user.create({
            data: {
                username,
                password: hashedPassword,
                firstName,
                lastName,
                email
            },
            select: {
                id:true
            }
        })

        const token = jwt.sign(newUser,SECRET_PASSWORD,{expiresIn: "1hr"});

        console.log("User has been created");

        return res.status(HTTPStatusCode.OK).json({
            message: "User signed up successfully",
            token: token
        })
    }catch(err){
        console.log(err);
        return res.status(HTTPStatusCode.InternalServerError).json({
            message: "Try Again"
        })
    }
})

type LoginType = Omit<SignupType, 'firstName' | 'lastName' | 'email'>;
const LoginParams = z.object({
    username: z.string().min(1,{message: "Username cannot be empty"}),
    password: z.string().min(8,{message: "Password length cannot be less than 8 characters"}).max(15,{message: "Password length cannot be more than 15 characters"}),
})


app.post("/login",async (req,res) => {
    const params: LoginType = req.body;
    const parsedInput = LoginParams.safeParse(params);
    if(!parsedInput.success){
        return res.status(HTTPStatusCode.InvalidInput).json({
            message: "Cannot parse the input data"
        })
    }
    const username = parsedInput.data.username;
    const password = parsedInput.data.password;
    
    const existingUser = await prisma.user.findFirst({
        where: {
            username,
        },
        select: {
            id: true,
            password: true
        }
    })

    if(!existingUser){
        return res.status(HTTPStatusCode.InvalidInput).json({
            message: "User does not exists"
        })
    }

    const hashedPassword = await bcrypt.compare(password,existingUser.password)
    if(!hashedPassword){
        return res.status(HTTPStatusCode.InvalidInput).json({
            message: "Password is not correct"
        })
    }

    const token = jwt.sign(existingUser, SECRET_PASSWORD, {expiresIn: "1h"});
    if(!token){
        return res.status(HTTPStatusCode.InternalServerError).json({
            message: "JWT Token could not be generated"
        })
    }

    return res.status(HTTPStatusCode.OK).json({
        message: "Successfully login",
        token: token
    })
})

app.use(auth)

app.get("/get_todos", async (req,res) => {
    const {userId} = req.body;
    const response = await prisma.todo.findMany({
        where: {
            user: {
                id: userId
            }
        }
    })

    if(!response){
        return res.status(HTTPStatusCode.InternalServerError).json({
            message: "Todos cannot be fetched properly"
        })
    }

    return res.status(HTTPStatusCode.OK).json({
        message: "Todos fetched",
        todos: response
    })
})

app.post("/add_todos", async (req,res) => {
    const userId: number = Number((req as any).userid);
    const todoInput = req.body;
    const parseInput = TodoParams.safeParse(todoInput);
    if(!parseInput.success){
        return res.status(HTTPStatusCode.InternalServerError).json({
            message: "Todo cannot be added"
        })
    }
    const response = await prisma.todo.create({
        data: {
            title: todoInput.title, 
            description: todoInput.description, 
            done: todoInput.done,
            userId: userId
        },
        select: {
            id: true
        }
    });
    
    if(!response){
        return res.status(HTTPStatusCode.SomethingWentWrong).json({
            message: "Todos cannot added",
        })
    }
    
    return res.status(HTTPStatusCode.OK).json({
        message: "Todos added successfully"
    })
})

app.put("/update_todos", async (req,res) => {
    const userId: number = Number((req as any).userid);
    const todoId = req.body.id;
    if(!todoId){
        return res.status(HTTPStatusCode.SomethingWentWrong).json({
            message: "Todo Id not present"
        })
    }

    const updateParams: {
        title?: string,
        description?: string,
        done?:boolean
    } = {};

    const {title,description,done} = req.body;

    if(title !== undefined) updateParams.title = title;
    if(description !== undefined) updateParams.description = description;
    if(done !== undefined) updateParams.done = done;

    const updatedTodo = await prisma.todo.update({
        where: {
            id: todoId
        },
        data: updateParams,
        select: {
            id: true
        }
    })

    if(!updatedTodo){
        return res.status(HTTPStatusCode.InternalServerError).json({
            message: "Todo Cannot be updated"
        })
    }

    return res.status(HTTPStatusCode.OK).json({
        message: "Todo updated successfully"
    })
})

app.delete("/delete_todo",async (req,res) => {
    const todoId = req.body.id;
    const response = await prisma.todo.delete({
        where:{
            id: todoId
        },
        select:{
            id: true
        }
    })
    if(!response){
        return res.status(HTTPStatusCode.InternalServerError).json({
            message: "Cannot delete the todos"
        })
    }

    return res.status(HTTPStatusCode.OK).json({
        message: "Todo deleted successfully"
    })
})

app.listen(PORT, () => {
  console.log(`Server is listening on ${PORT}`);
});
