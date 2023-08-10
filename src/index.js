const express = require('express')
const cors = require('cors')
const app = express();
const error_middleware  = require('./middleware/error_middleware');
require("dotenv").config({ path: `./env/dev.env`});
require("./config/database")
const bodyParser = require('body-parser');
const userRouter = require("./routes/users.routes")
const votingRouter = require("./routes/voting.routes")
const electionRouter = require("./routes/elections.routes")

app.use(cors());
app.use(express.json());

//use express router
app.use('/', (req,res,next)=>{
    // console.log("here outside",res.methods)
    if(req.methods == 'OPTIONS'){
        // console.log("here")
        return res.json({message:"success"})
    }
    next()
})
app.use (express.urlencoded({extended:false}))
app.use('/api/v1',userRouter);
app.use('/api/v1',votingRouter);
app.use('/api/v1',electionRouter);
app.use('/api/v1',votingRouter) 
app.use(error_middleware);
app.use(bodyParser.json());
const PORT = process.env.PORT;

app.listen(PORT, () => {
    console.log('Server is up on port ' + PORT )
})