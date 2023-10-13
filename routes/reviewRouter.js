const { Router } = require('express')
const { getAllReview, createReview, updateAllReview, updateReview, deleteReview } = require('../service/reviewService.js')
const authenticationMiddleware = require("../middleware/authentication-middleware.js");
const { checkRole } = require("../middleware/checkRole.js");




const reviewRouter = Router()

reviewRouter.get('/', authenticationMiddleware, checkRole(["admin"]),getAllReview)
reviewRouter.post('/', authenticationMiddleware, checkRole(["approver", "reviewer"]), createReview)
reviewRouter.put('/:id', authenticationMiddleware, checkRole(["approver", "reviewer"]), updateAllReview)
reviewRouter.patch('/:id', authenticationMiddleware, checkRole(["approver", "reviewer"]), updateReview)
reviewRouter.delete("/:id", authenticationMiddleware, checkRole(["approver", "reviewer", "admin"]), deleteReview);

module.exports = reviewRouter  