const bcrypt = require("bcryptjs");
const jsonwt = require("jsonwebtoken");
const Election = require("../models/election.model");
const { electionType } = require('../utils/constant')
const ErrorHandler = require("../utils/errorHandler")

const createElection = async(req,res,next)=>{
    try{
        const { name,startDate,endDate,candidates,type,area,date,location,areaId,state,district }=req.body;
        if(!name || !startDate || !endDate || !candidates || !type || !area || !date || !location || !areaId || !state || !district){
            throw new ErrorHandler
            ("Enter the required fields", 400); 
          }
       else{
        const data = await Election.create(req.body);
        res.status(201).json({
            success:true,
            data:data
        })
       }
        }

    catch(error){
        next(error)
    }
}

const getElection = async (req, res, next) => {
    try {
        const query = req.query.search;
        let data = {};
        const viewElection =await Election.find(
           query ? {
                "$or":[
                    {area:{$regex:query,$options: "i"}},
                    {areaId:{$regex:query,$options: "i"}},
                    {location:{$regex:query,$options: "i"}},
                    {state:{$regex:query,$options: "i"}},
                    {district:{$regex:query,$options: "i"}}
                ]
            }:{}
        )
        const currentDate = new Date();
        const pastElections = await Election.find({ endDate: { $lt: currentDate } }).sort({ startDate: -1 });
        const upcomingElections = await Election.find({ startDate: { $gt: currentDate } }).sort({ startDate: 1 });

        data.allElection = viewElection;
        
        data.pastElection = pastElections;
        data.upComingElection = upcomingElections;

        res.status(200).json({ 
            success: true,
            data: data
        })
    } catch (error) {
        next(error)
    }
}

module.exports = { createElection,getElection}