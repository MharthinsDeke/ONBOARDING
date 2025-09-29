const mongoose = require('mongoose')
require('dotenv').config();
const DB = process.env.MONGODB_URL

mongoose.connect(DB).then(()=>{
    console.log(`Database connected successfully`);
    
})
.catch((error)=>{
    console.log(`Error Connecting to database`, error.message);
    
})