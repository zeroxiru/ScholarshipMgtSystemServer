require('dotenv').config()
const express = require('express')
const cors = require('cors')
require('dotenv').config()
const cookieParser = require('cookie-parser')
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb')
const jwt = require('jsonwebtoken')
const morgan = require('morgan')

const port = process.env.PORT || 4000
const app = express()
// middleware
const corsOptions = {
  origin: ['http://localhost:5173', 'http://localhost:5174', 'http://localhost:5175','https://phfinalproject.web.app'],
  credentials: true,
  optionSuccessStatus: 200,
}
app.use(cors(corsOptions))

app.use(express.json())
app.use(cookieParser())
app.use(morgan('dev'))

const verifyToken = async (req, res, next) => {
  const token = req.cookies?.token

  if (!token) {
    return res.status(401).send({ message: 'unauthorized access' })
  }
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      console.log(err)
      return res.status(401).send({ message: 'unauthorized access' })
    }
    req.user = decoded
    next()
  })
}

// const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.mq0mae1.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.fmsye.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`
//  const uri =`mongodb+srv://<db_username>:<db_password>@cluster0.fmsye.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
})
async function run() {
  try {
    //await client.connect();
    const db = client.db('finalProjectDb')

    const usersCollection = db.collection('users')
    const scholarshipsCollection = db.collection('scholarshipsData')
    const applicantsCollection = db.collection('scholarshipsApplicantsData')
    const scholarshipApplicationsCollection = db.collection('scholarshipApplications');
    const reviewCollection = db.collection('reviewData');
    

    app.post('/jwt', async (req, res) => {
      const email = req.body
      const token = jwt.sign(email, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: '365d',
      })
      res
        .cookie('token', token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
        })
        .send({ success: true })
    })
    
    // verify admin middleware
    const verifyAdmin = async (req, res, next) => {
      // console.log('data from verifyToken middleware--->', req.user?.email)
      const email = req.user?.email
      const query = { email }
      const result = await usersCollection.findOne(query)
      if (!result || result?.role !== 'Admin')
        return res
          .status(403)
          .send({ message: 'Forbidden Access! Admin Only Actions!' })

      next()
    }
    // verify moderator middleware
    const verifyModerator = async (req, res, next) => {
      console.log('data from verifyToken middleware--->', req.user?.email)
      try {
        const email = req.user?.email; // Comes from verifyToken
        if (!email) {
          return res.status(401).send({ message: 'Unauthorized Access!' });
        }

        const query = { email }; // Ensure exact email match
        const result = await usersCollection.findOne(query);

        if (!result || result?.role !== 'Moderator') {
          return res
            .status(403)
            .send({ message: 'Forbidden Access! Moderator-only actions!' });
        }

        // Allow request to proceed
        next();
      } catch (error) {
        console.error('Error in verifyModerator middleware:', error);
        res.status(500).send({ message: 'Internal Server Error!' });
      }
    };

    //save or update
    app.post('/users/:email', async (req, res) => {
      const email = req.params.email;
      const query = { email }
      const user = req.body;
      console.log('Recieved User:', user);
      //check if user exists in db

      const isExist = await usersCollection.findOne(query)
      if (isExist) {
        return res.send(isExist)
      }
      const result = await usersCollection.insertOne({
        ...user,
        name: user.name || "Anonymous User",
        image: user.image || "Image is N/A",
        role: 'user',
        timeStamp: Date.now()
      })
      res.send(result)
    })

    // manage user status and role
    app.patch('/users/:email', verifyToken, verifyAdmin, async (req, res) => {
      const email = req.params.email
      const query = { email }
      const user = await usersCollection.findOne(query)
      if (!user || user?.status === 'Requested')
        return res
          .status(400)
          .send('You have already requested, wait for some time.')
      const updateDoc = {
        $set: {
          status: "Requested",
        },
      }
      const result = await usersCollection.updateOne(query, updateDoc)
      console.log(result)
      res.send(result)

    })

    //update a user role & status
    app.patch('/user/role/:email', verifyToken, async (req, res) => {
      const email = req.params.email
      const { role, status } = req.body
      const filter = { email }
      const updateDoc = {
        $set: { role, status: "verified" }
      }
      const result = await usersCollection.updateOne(filter, updateDoc)
      res.send(result)
    })

    // get user role
    app.get('/users/role/:email', async (req, res) => {
      const email = req.params.email
      const result = await usersCollection.findOne({ email })
      res.send({ role: result?.role })
    })

    // get all user data
    app.get('/all-users/:email', verifyToken, verifyAdmin, async (req, res) => {
      const email = req.params.email
      const query = { email: { $ne: email } }
      const result = await usersCollection.find(query).toArray()
      res.send(result)
    })
    // add scholarship
    app.post('/addScholarship', verifyToken, async (req, res) => {
      const scholarship = req.body;
      const result = await scholarshipsCollection.insertOne(scholarship)
      res.send(result);
    })

    app.get('/filtered-scholarships', async (req, res) => {
      try {
        const { minApplicationFees } = req.query;

        // Debugging: Log the collection being used
        console.log('Using scholarshipsCollection:', scholarshipsCollection.namespace);

        // Build the query
        const query = minApplicationFees
          ? { applicationFees: { $gte: parseFloat(minApplicationFees) } }
          : {};
        console.log('Query:', query);

        // Fetch data from scholarshipsCollection
        const filteredScholarships = await scholarshipsCollection
          .find(query)
          .sort({ applicationFees: 1, postDate: -1 }) // Low fees and recent postDate
          .limit(6)
          .toArray();
        console.log('Result:', filteredScholarships);

        res.send({ success: true, data: filteredScholarships });
      } catch (error) {
        console.error('Error in /filtered-scholarships endpoint:', error);
        res.status(500).send({
          success: false,
          message: 'Failed to fetch scholarships.',
        });
      }
    });
    
    app.get('/scholarships', async (req, res) => {
      try {
        const { scholarshipType, search } = req.query;
        let query = {}
        // add scholarshipType Filter if Provided
        if (scholarshipType) {
          query.scholarshipCategory = scholarshipType
        }
        if (search) {
          query.$or = [
            { scholarshipName: { $regex: search, $options: 'i' } },
            { universityName: { $regex: search, $options: 'i' } },
            { degree: { $regex: search, $options: 'i' } }
          ]
        }

        const scholarships = await scholarshipsCollection.find(query).toArray();
        res.send({ success: true, data: scholarships });
      } catch (error) {
        console.error('Error in /scholarships endpoint:', error);
        res.status(500).send({
          success: false,
          message: 'Failed to fetch scholarships.',
        });
      }
    });
    // get a single scholarship data from db
    app.get('/scholarships/:id', async (req, res) => {
      const id = req.params.id
      const query = { _id: new ObjectId(id) }
      const result = await scholarshipsCollection.findOne(query)
      res.send(result);
    })
    app.post('/dashboard/applicants', async (req, res) => {
      try {
        const applicantData = req.body;

        // Insert applicant data into the database
        const result = await applicantsCollection.insertOne(applicantData);

        // Respond with the ID of the new applicant
        res.status(201).json({ id: result.insertedId });
      } catch (error) {
        console.error('Error saving applicant data:', error);
        res.status(500).json({ message: 'Failed to save applicant data' });
      }
    })

    // POST /api/dashboard/apply-scholarships
    app.post('/dashboard/apply-scholarships', async (req, res) => {
      try {
        const {
          userName,
          userEmail,
          userId,
          scholarshipId,
          universityName,
          scholarshipCategory,
          subjectCategory,
          applicantId,
          date,
          status,
        } = req.body;

        // Create the application data object
        const applicationData = {
          userName,
          userEmail,
          userId: new ObjectId(userId), // Ensure IDs are properly formatted
          scholarshipId: new ObjectId(scholarshipId),
          universityName,
          scholarshipCategory,
          subjectCategory,
          applicantId: new ObjectId(applicantId),
          date: new Date(date), // Ensure the date is properly formatted
          status: 'Pending'
        };

        // Insert application data into the database
        const result = await scholarshipApplicationsCollection.insertOne(applicationData);

        // Respond with the ID of the new application
        res.status(201).json({ id: result.insertedId });
      } catch (error) {
        console.error('Error saving scholarship application data:', error);
        res.status(500).json({ message: 'Failed to save scholarship application data' });
      }
    });

    // get /my-application/:email
    app.get('/dashboard/my-applications/:email', async (req, res) => {
      try {
        const { email } = req.params;

        const pipeline = [
          {
            $match: { userEmail: email },
          },
          {
            $addFields: {
              scholarshipId: { $toObjectId: '$scholarshipId' },
            },
          },
          {
            $lookup: {
              from: 'scholarshipsData',
              localField: 'scholarshipId',
              foreignField: '_id',
              as: 'scholarshipDetails',
            },
          },
          {
            $unwind: {
              path: '$scholarshipDetails',
              preserveNullAndEmptyArrays: true,
            },
          },
          {
            $project: {
              _id: 1,
              scholarshipId: 1,
              universityName: '$scholarshipDetails.universityName',
              universityAddress: {
                $concat: [
                  { $ifNull: ['$scholarshipDetails.universityCity', 'N/A'] },
                  ', ',
                  { $ifNull: ['$scholarshipDetails.universityCountry', 'N/A'] },
                ],
              },
              applicationFeedback: 1,
              applicationStatus: { $ifNull: ['$status', 'N/A'] },
              applicantId: 1,
              scholarshipDetails: 1,
            },
          },
        ];

        const applications = await scholarshipApplicationsCollection.aggregate(pipeline).toArray();

        if (!applications.length) {
          return res.status(404).json({ message: 'No applications found for this user.' });
        }
        // Fetch applicant details for each application using `find`
        const applicantIds = applications
          .filter((app) => app.applicantId)
          .map((app) => app.applicantId);

        const applicants = await applicantsCollection
          .find({ _id: { $in: applicantIds.map(id => new ObjectId(id)) } })
          .toArray();

        const mergeApplications = applications.map(app => {
          const applicantDetail = applicants.find(
            applicant => applicant._id.toString() === app.applicantId.toString()
          );
          return {
            _id: app._id,
            scholarshipId: app.scholarshipId,
            universityName: app.scholarshipDetails?.universityName,
            universityAddress: app?.universityAddress,
            applicationFeedback: app?.feedback || 'N/A',
            subjectCategory: app.scholarshipDetails?.subjectCategory,
            appliedDegree: applicantDetail?.applyingDegree || 'No Degree Information',
            applicationFees: app.scholarshipDetails?.applicationFees,
            serviceCharge: app.scholarshipDetails?.serviceCharge,
            applicationStatus: app?.applicationStatus || 'Unknown',
          }

        })

        res.status(200).json(mergeApplications);
      } catch (error) {
        console.error('Error fetching applications:', error);
        res.status(500).json({ message: 'Internal server error' });
      }
    });

    // cancel/delete an order
    app.delete('/dashboard/applications/:id', verifyToken, async (req, res) => {
      const id = req.params.id
      const query = { _id: new ObjectId(id) }
      const application = await scholarshipApplicationsCollection.findOne(query)
      if (application.status === "Approved") return res.status(409).send("Cannot cancel once the application is Approved")
      const result = await scholarshipApplicationsCollection.deleteOne(query)
      res.send(result)
    })

    // update the my application by endpoints

    app.put('/dashboard/applications/:id', verifyToken, async (req, res) => {
      const applicationId = req.params.id; // Extract application ID from the URL
      const {
        universityName,
        subjectCategory,
        universityCountry,
        universityCity,
        applicationFees,
        serviceCharge,
        appliedDegree,
        applicationStatus,
      } = req.body;

      try {
        // Step 1: Find the application in scholarshipApplicationsCollection
        const application = await scholarshipApplicationsCollection.findOne({ _id: new ObjectId(applicationId) });

        if (!application) {
          return res.status(404).json({ message: 'Application not found' });
        }

        // Step 2: Find the scholarship in scholarshipsCollection
        const scholarship = await scholarshipsCollection.findOne({ _id: new ObjectId(application.scholarshipId) });

        if (!scholarship) {
          return res.status(404).json({ message: 'Scholarship not found' });
        }

        const applicant = await applicantsCollection.findOne({ _id: new ObjectId(application.applicantId) })

        if (!applicant) {
          return res.status(404).json({ message: 'applicant not found' });
        }
        // Step 3: Update the application (if necessary)
        if (applicationStatus) {
          const applicationUpdateResult = await scholarshipApplicationsCollection.updateOne(
            { _id: new ObjectId(applicationId) },
            {
              $set: {
                ...(applicationStatus && { status: applicationStatus }),

              },
            }
          );



          if (applicationUpdateResult.matchedCount === 0) {
            return res.status(404).json({ message: 'Failed to update application details' });
          }
        }
        if (appliedDegree) {
          const applicantUpdateResult = await applicantsCollection.updateOne(
            { _id: new ObjectId(application.applicantId) },
            {
              $set: {
                ...(appliedDegree && { applyingDegree: appliedDegree }),
              },
            }
          );

          if (applicantUpdateResult.matchedCount === 0) {
            return res.status(404).json({ message: 'Failed to update application details' });
          }
        }


        // Step 4: Update the scholarship (if necessary)
        if (
          universityName ||
          universityCountry ||
          universityCity ||
          subjectCategory ||
          applicationFees ||
          serviceCharge
        ) {
          const universityAddress = `${universityCity || ''}, ${universityCountry || ''}`.trim().replace(/^,|,$/g, '');

          const scholarshipUpdateResult = await scholarshipsCollection.updateOne(
            { _id: new ObjectId(application.scholarshipId) },
            {
              $set: {
                ...(universityName && { universityName }),
                ...(subjectCategory && { subjectCategory }),
                ...(applicationFees && { applicationFees }),
                ...(serviceCharge && { serviceCharge }),
                ...(universityAddress && { universityAddress }),
              },
            }
          );

          if (scholarshipUpdateResult.matchedCount === 0) {
            return res.status(404).json({ message: 'Failed to update scholarship details' });
          }
        }

        res.status(200).json({
          success: true,
          message: 'Application and scholarship details updated successfully',
        });
      } catch (error) {
        console.error('Error updating details:', error.message);
        res.status(500).json({ message: 'Internal server error', error: error.message });
      }
    });


    app.get('/dashboard/applications/:id', async (req, res) => {
      const { id } = req.params;

      try {
        // Fetch application details by ID
        const application = await scholarshipApplicationsCollection.findOne({ _id: new ObjectId(id) });

        if (!application) {
          return res.status(404).json({ error: 'Application not found' });
        }

        // Fetch additional details based on scholarshipId
        const scholarshipDetails = await scholarshipsCollection.findOne({ _id: new ObjectId(application.scholarshipId) });

        if (!scholarshipDetails) {
          return res.status(404).json({ error: 'Scholarship details not found' });
        }

        // Combine the application data with the additional scholarship details
        const combinedData = {
          ...application,
          universityImage: scholarshipDetails.universityImage,
          scholarshipDescription: scholarshipDetails.description,
          scholarshipEligibility: scholarshipDetails.eligibility,
          tuitionFees: scholarshipDetails.tuitionFees,
          applicationFees: scholarshipDetails.applicationFees,
          serviceCharge: scholarshipDetails.serviceCharge,
          universityWorldRank: scholarshipDetails.universityWorldRank,
          applicationDeadline: scholarshipDetails.applicationDeadline,
        };

        res.status(200).json(combinedData); // Send the combined data
      } catch (error) {
        console.error('Error fetching application details:', error);
        res.status(500).json({ error: 'Failed to fetch application details' });
      }
    });

    app.post('/dashboard/reviews', async (req, res) => {
      try {
        const reviewData = req.body;
        const result = await reviewCollection.insertOne(reviewData)

        res.status(201).json({ message: 'Review saved successfully!', result });
      } catch (error) {
        console.error('Error saving review:', error);
        res.status(500).json({ message: 'Failed to save review' });
      }
    });

    // get /dashboard/my-reviews/:email
    app.get('/dashboard/my-reviews/:email', async (req, res) => {
      try {

        const { email } = req.params;
        const pipeline = [
          {
            $match: { userEmail: email },
          },
          {
            $addFields: {
              scholarshipId: { $toObjectId: '$scholarshipId' },
            },
          },
          {
            $lookup: {
              from: 'scholarshipsData',
              localField: 'scholarshipId',
              foreignField: '_id',
              as: 'scholarshipDetails'
            },
          },
          {
            $unwind: {
              path: '$scholarshipDetails',
              preserveNullAndEmptyArrays: true,
            },
          },
          {
            $project: {
              _id: 1,
              comment: 1,
              reviewDate: 1,
              universityName: 1,
              scholarshipName: '$scholarshipDetails.scholarshipName',
            },
          },
        ]
        const reviews = await reviewCollection.aggregate(pipeline).toArray();

        if (!reviews.length) {
          return res.status(404).json({ message: 'No reviews found for this user.' });
        }

        // Return the reviews
        res.status(200).json(reviews);
        console.log(reviews);
      } catch (error) {
        console.error('Error fetching reviews:', error);
        res.status(500).json({ message: 'Internal server error' });
      }

    })
    // delete a review from my-review
    app.delete('/dashboard/review/:id', verifyToken, async (req, res) => {
      const id = req.params.id
      const query = { _id: new ObjectId(id) }
      const review = await reviewCollection.findOne(query)
      const result = await reviewCollection.deleteOne(review)
      res.send(result)
    })
    app.put('/dashboard/review/:id', async (req, res) => {
      try {
        const { id } = req.params; // Get the review ID from the request parameters
        const { comment, reviewDate, universityName, scholarshipId } = req.body; // Destructure updated fields from request body

        // Check if the ID is a valid ObjectId
        if (!ObjectId.isValid(id)) {
          return res.status(400).json({ message: 'Invalid review ID' });
        }

        // Build the update object dynamically based on provided fields
        const updateFields = {};

        if (comment) updateFields.comment = comment;
        if (reviewDate) updateFields.reviewDate = reviewDate;
        if (universityName) updateFields.universityName = universityName;

        // If scholarshipId is provided, fetch the scholarshipName from the scholarshipsData collection
        if (scholarshipId) {
          if (!ObjectId.isValid(scholarshipId)) {
            return res.status(400).json({ message: 'Invalid scholarship ID' });
          }

          const scholarship = await scholarshipsCollection.findOne({
            _id: new ObjectId(scholarshipId),
          });

          if (!scholarship) {
            return res.status(404).json({ message: 'Scholarship not found' });
          }

          updateFields.scholarshipId = scholarshipId;
          updateFields.scholarshipName = scholarship.scholarshipName; // Add the scholarshipName to the updateFields
        }

        // Perform the update operation
        const result = await reviewCollection.updateOne(
          { _id: new ObjectId(id) }, // Find the document by its ID
          { $set: updateFields } // Update the specified fields
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({ message: 'Review not found' });
        }

        res.status(200).json({ message: 'Review updated successfully', updatedFields: updateFields });
      } catch (error) {
        console.error('Error updating review:', error);
        res.status(500).json({ message: 'Internal server error' });
      }
    });

    // Fetch all scholarships by moderator
    app.get('/dashboard/moderator/scholarships/', verifyToken, verifyModerator, async (req, res) => {
      try {

        const scholarships = await scholarshipsCollection.find({ 'moderator.email': req.user.email }).toArray();
        res.status(200).json({ data: scholarships });

      } catch (error) {
        console.error("Error fetching scholarships:", error);
        res.status(500).json({ message: "Internal server error" });
      }
    });

     // delete  scholarships by moderator
   
    app.delete('/dashboard/moderator/reviews/:id', verifyToken, verifyModerator, async (req, res) => {
      try {
        const id = req.params.id;
    
        // Validate ObjectId
        if (!ObjectId.isValid(id)) {
          return res.status(400).json({ error: "Invalid ID format" });
        }
    
        const query = { _id: new ObjectId(id) };
        const review = await reviewCollection.findOne(query);
    
        if (!review) {
          return res.status(404).json({ error: "Review not found" });
        }
    
        const result = await reviewCollection.deleteOne(query);
    
        if (result.deletedCount === 1) {
          res.status(200).json({ message: "Review deleted successfully" });
        } else {
          res.status(500).json({ error: "Failed to delete review" });
        }
      } catch (error) {
        console.error("Error deleting review:", error);
        res.status(500).json({ error: "Internal Server Error", details: error.message });
      }
    });
    

    //get all reviews
    app.get("/dashboard/moderator/reviews", verifyToken, verifyModerator, async (req, res) => {
      try {
        const reviews = await reviewCollection.find().toArray();
        res.status(200).json(reviews);
      } catch (err) {
        res.status(500).json({ error: "Failed to fetch reviews" });
      }
    });

    app.delete("/dashboard/moderator/reviews/:id", verifyToken, verifyModerator, async (req, res) => {
      const { id } = req.params;
    
      try {
        const review = await reviewCollection.findByIdAndDelete(id);
    
        if (review) {
          res.status(200).json({ message: "Review deleted successfully" });
        } else {
          res.status(404).json({ error: "Review not found" });
        }
      } catch (err) {
        res.status(500).json({ error: "Failed to delete review" });
      }
    });
   // update moderator scholarship
    app.put("/dashboard/moderator/scholarship/:id", async (req, res) => {
      const { id } = req.params; // Get the scholarship ID from URL
      const updatedData = req.body; // Get the updated data from request body
    
      try {
        // Update the scholarship in the database
        const updatedScholarship = await Scholarship.findByIdAndUpdate(
          id, // Scholarship ID
          updatedData, // Updated fields
          { new: true } // Return the updated document
        );
    
        if (updatedScholarship) {
          res
            .status(200)
            .json({ message: "Scholarship updated successfully", data: updatedScholarship });
        } else {
          res.status(404).json({ error: "Scholarship not found" });
        }
      } catch (error) {
        res.status(500).json({ error: "Failed to update scholarship" });
      }
    });
   
app.get('/scholarships/:id/reviews', async (req, res) => {
  try {
    const scholarshipId = req.params.id;

    // Query to find all reviews for the given scholarshipId
    const query = { scholarshipId: scholarshipId };
    const reviews = await reviewCollection.find(query).toArray();

    if (reviews.length === 0) {
      return res.status(404).json({ message: 'No reviews found for this scholarship.' });
    }

    res.status(200).json(reviews);
  } catch (error) {
    console.error('Error fetching reviews:', error);
    res.status(500).json({ error: 'An error occurred while fetching reviews.' });
  }
});
/**
 * ✅ Moderator-only Route: Get All Applications
 */
app.get("/dashboard/all-applications", verifyToken, verifyModerator, async (req, res) => {
  try {
    
    const applications = await scholarshipApplicationsCollection.find().toArray();
    res.status(200).json(applications);
  } catch (error) {
    console.error("Error fetching applications:", error);
    res.status(500).json({ message: "Failed to fetch applications", error });
  }
});

app.patch("/dashboard/update-status/:id", async (req, res) => {
  try {
    const applicationId = req.params.id;
    const query = { _id: new ObjectId(applicationId) };

    // Fetch the existing application
    const application = await db.collection("scholarshipApplications").findOne(query);
    if (!application) {
      return res.status(400).send("This application is not available.");
    }
     
    if (application.status === "Rejected") {
      return res.status(400).send("This application is already rejected.");
    }
    // Prepare the update document
    const updateDoc = { $set: { status: "Rejected" } };

    // Update the status in the database
    const result = await db.collection("scholarshipApplications").updateOne(query, updateDoc);

    if (result.modifiedCount > 0) {
      res.status(200).json({ message: "Application status updated to Rejected." });
    } else {
      res.status(400).json({ message: "Failed to update application status." });
    }

  } catch (error) {
    console.error("Error updating application status:", error);
    res.status(500).send("Server error while updating status.");
  }
});
   
    

   
    // Logout
    app.get('/logout', async (req, res) => {
      try {
        res
          .clearCookie('token', {
            maxAge: 0,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
          })
          .send({ success: true })
      } catch (err) {
        res.status(500).send(err)
      }
    })

    app.get('/admin-stat', verifyToken, verifyAdmin, async (req, res) => { 
      const totalUsers = await usersCollection.estimatedDocumentCount();
      const totalScholarships = await scholarshipsCollection.estimatedDocumentCount()
      res.send({totalScholarships, totalUsers})
    })

    // Send a ping to confirm a successful connection
    // await client.db('admin').command({ ping: 1 })
    // console.log(
    //   'Pinged your deployment. You successfully connected to MongoDB!'
    // )
  } finally {
    // Ensures that the client will close when you finish/error
  }
}
run().catch(console.dir)

app.get('/', (req, res) => {
  res.send('Hello from Scholarship Management System Server..')
})

app.listen(port, () => {
  console.log(`Scholarship Management System is running on port ${port}`)
})
