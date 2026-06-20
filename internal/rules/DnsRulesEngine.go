package rules

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"sleuth/internal/db"
	"slices"
	"strconv"
	"strings"
)

type DNSRulesEngine struct {
	db       *db.Db
	settings *db.Settings
}

func Init(db *db.Db, settings *db.Settings) *DNSRulesEngine {
	return &DNSRulesEngine{
		db:       db,
		settings: settings,
	}
}

func stringPtr(val string) *string {
	return &val
}

func (re *DNSRulesEngine) InitDefaults() {

	if len(re.db.GetDNSCategories()) == 0 && len(re.db.GetDNSRuleSets()) == 0 {
		type categorySeed struct {
			ID     string
			Name   string
			Parent *string
		}

		seed := []categorySeed{
			{"SC", "Service Classification", nil},
			{"IAB", "Content Classification", nil},

			// ---------------- IAB1 ----------------
			{"IAB1", "Arts & Entertainment", stringPtr("IAB")},
			{"IAB1-1", "Books & Literature", stringPtr("IAB1")},
			{"IAB1-2", "Celebrity Fan/Gossip", stringPtr("IAB1")},
			{"IAB1-3", "Fine Art", stringPtr("IAB1")},
			{"IAB1-4", "Humor", stringPtr("IAB1")},
			{"IAB1-5", "Movies", stringPtr("IAB1")},
			{"IAB1-6", "Music", stringPtr("IAB1")},
			{"IAB1-7", "Television", stringPtr("IAB1")},

			// ---------------- IAB2 ----------------
			{"IAB2", "Automotive", stringPtr("IAB")},
			{"IAB2-1", "Auto Parts", stringPtr("IAB2")},
			{"IAB2-2", "Auto Repair", stringPtr("IAB2")},
			{"IAB2-3", "Buying/Selling Cars", stringPtr("IAB2")},
			{"IAB2-4", "Car Culture", stringPtr("IAB2")},
			{"IAB2-5", "Certified Pre-Owned", stringPtr("IAB2")},
			{"IAB2-6", "Convertible", stringPtr("IAB2")},
			{"IAB2-7", "Coupe", stringPtr("IAB2")},
			{"IAB2-8", "Crossover", stringPtr("IAB2")},
			{"IAB2-9", "Diesel", stringPtr("IAB2")},
			{"IAB2-10", "Electric Vehicle", stringPtr("IAB2")},
			{"IAB2-11", "Hatchback", stringPtr("IAB2")},
			{"IAB2-12", "Hybrid", stringPtr("IAB2")},
			{"IAB2-13", "Luxury", stringPtr("IAB2")},
			{"IAB2-14", "Minivan", stringPtr("IAB2")},
			{"IAB2-15", "Motorcycles", stringPtr("IAB2")},
			{"IAB2-16", "Off-Road Vehicles", stringPtr("IAB2")},
			{"IAB2-17", "Performance Vehicles", stringPtr("IAB2")},
			{"IAB2-18", "Pickup", stringPtr("IAB2")},
			{"IAB2-19", "Road-Side Assistance", stringPtr("IAB2")},
			{"IAB2-20", "Sedan", stringPtr("IAB2")},
			{"IAB2-21", "Trucks & Accessories", stringPtr("IAB2")},
			{"IAB2-22", "Vintage Cars", stringPtr("IAB2")},
			{"IAB2-23", "Wagon", stringPtr("IAB2")},

			// ---------------- IAB3 ----------------
			{"IAB3", "Business", stringPtr("IAB")},
			{"IAB3-1", "Advertising", stringPtr("IAB3")},
			{"IAB3-2", "Agriculture", stringPtr("IAB3")},
			{"IAB3-3", "Biotech/Biomedical", stringPtr("IAB3")},
			{"IAB3-4", "Business Software", stringPtr("IAB3")},
			{"IAB3-5", "Construction", stringPtr("IAB3")},
			{"IAB3-6", "Forestry", stringPtr("IAB3")},
			{"IAB3-7", "Government", stringPtr("IAB3")},
			{"IAB3-8", "Green Solutions", stringPtr("IAB3")},
			{"IAB3-9", "Human Resources", stringPtr("IAB3")},
			{"IAB3-10", "Logistics", stringPtr("IAB3")},
			{"IAB3-11", "Marketing", stringPtr("IAB3")},
			{"IAB3-12", "Metals", stringPtr("IAB3")},

			// ---------------- IAB4 ----------------
			{"IAB4", "Careers", stringPtr("IAB")},
			{"IAB4-1", "Career Planning", stringPtr("IAB4")},
			{"IAB4-2", "College", stringPtr("IAB4")},
			{"IAB4-3", "Financial Aid", stringPtr("IAB4")},
			{"IAB4-4", "Job Fairs", stringPtr("IAB4")},
			{"IAB4-5", "Job Search", stringPtr("IAB4")},
			{"IAB4-6", "Resume Writing/Advice", stringPtr("IAB4")},
			{"IAB4-7", "Nursing", stringPtr("IAB4")},
			{"IAB4-8", "Scholarships", stringPtr("IAB4")},
			{"IAB4-9", "Telecommuting", stringPtr("IAB4")},
			{"IAB4-10", "U.S. Military", stringPtr("IAB4")},
			{"IAB4-11", "Career Advice", stringPtr("IAB4")},

			// ---------------- IAB5 ----------------
			{"IAB5", "Education", stringPtr("IAB")},
			{"IAB5-1", "7-12 Education", stringPtr("IAB5")},
			{"IAB5-2", "Adult Education", stringPtr("IAB5")},
			{"IAB5-3", "Art History", stringPtr("IAB5")},
			{"IAB5-4", "College Administration", stringPtr("IAB5")},
			{"IAB5-5", "College Life", stringPtr("IAB5")},
			{"IAB5-6", "Distance Learning", stringPtr("IAB5")},
			{"IAB5-7", "English as a 2nd Language", stringPtr("IAB5")},
			{"IAB5-8", "Language Learning", stringPtr("IAB5")},
			{"IAB5-9", "Graduate School", stringPtr("IAB5")},
			{"IAB5-10", "Homeschooling", stringPtr("IAB5")},
			{"IAB5-11", "Homework/Study Tips", stringPtr("IAB5")},
			{"IAB5-12", "K-6 Educators", stringPtr("IAB5")},
			{"IAB5-13", "Private School", stringPtr("IAB5")},
			{"IAB5-14", "Special Education", stringPtr("IAB5")},
			{"IAB5-15", "Studying Business", stringPtr("IAB5")},

			// ---------------- IAB6 ----------------
			{"IAB6", "Family & Parenting", stringPtr("IAB")},
			{"IAB6-1", "Adoption", stringPtr("IAB6")},
			{"IAB6-2", "Babies & Toddlers", stringPtr("IAB6")},
			{"IAB6-3", "Daycare/Pre School", stringPtr("IAB6")},
			{"IAB6-4", "Family Internet", stringPtr("IAB6")},
			{"IAB6-5", "Parenting - K-6 Kids", stringPtr("IAB6")},
			{"IAB6-6", "Parenting Teens", stringPtr("IAB6")},
			{"IAB6-7", "Pregnancy", stringPtr("IAB6")},
			{"IAB6-8", "Special Needs Kids", stringPtr("IAB6")},
			{"IAB6-9", "Eldercare", stringPtr("IAB6")},

			// ---------------- IAB7 ----------------
			{"IAB7", "Health & Fitness", stringPtr("IAB")},
			{"IAB7-1", "Exercise", stringPtr("IAB7")},
			{"IAB7-2", "A.D.D.", stringPtr("IAB7")},
			{"IAB7-3", "AIDS/HIV", stringPtr("IAB7")},
			{"IAB7-4", "Allergies", stringPtr("IAB7")},
			{"IAB7-5", "Alternative Medicine", stringPtr("IAB7")},
			{"IAB7-6", "Arthritis", stringPtr("IAB7")},
			{"IAB7-7", "Asthma", stringPtr("IAB7")},
			{"IAB7-8", "Autism/PDD", stringPtr("IAB7")},
			{"IAB7-9", "Bipolar Disorder", stringPtr("IAB7")},
			{"IAB7-10", "Brain Tumor", stringPtr("IAB7")},
			{"IAB7-11", "Cancer", stringPtr("IAB7")},
			{"IAB7-12", "Cholesterol", stringPtr("IAB7")},
			{"IAB7-13", "Chronic Fatigue Syndrome", stringPtr("IAB7")},
			{"IAB7-14", "Chronic Pain", stringPtr("IAB7")},
			{"IAB7-15", "Cold & Flu", stringPtr("IAB7")},
			{"IAB7-16", "Deafness", stringPtr("IAB7")},
			{"IAB7-17", "Dental Care", stringPtr("IAB7")},
			{"IAB7-18", "Depression", stringPtr("IAB7")},
			{"IAB7-19", "Dermatology", stringPtr("IAB7")},
			{"IAB7-20", "Diabetes", stringPtr("IAB7")},
			{"IAB7-21", "Epilepsy", stringPtr("IAB7")},
			{"IAB7-22", "GERD/Acid Reflux", stringPtr("IAB7")},
			{"IAB7-23", "Headaches/Migraines", stringPtr("IAB7")},
			{"IAB7-24", "Heart Disease", stringPtr("IAB7")},
			{"IAB7-25", "Herbs for Health", stringPtr("IAB7")},
			{"IAB7-26", "Holistic Healing", stringPtr("IAB7")},
			{"IAB7-27", "IBS/Crohn’s Disease", stringPtr("IAB7")},
			{"IAB7-28", "Incest/Abuse Support", stringPtr("IAB7")},
			{"IAB7-29", "Incontinence", stringPtr("IAB7")},
			{"IAB7-30", "Infertility", stringPtr("IAB7")},
			{"IAB7-31", "Men’s Health", stringPtr("IAB7")},
			{"IAB7-32", "Nutrition", stringPtr("IAB7")},
			{"IAB7-33", "Orthopedics", stringPtr("IAB7")},
			{"IAB7-34", "Panic/Anxiety Disorders", stringPtr("IAB7")},
			{"IAB7-35", "Pediatrics", stringPtr("IAB7")},
			{"IAB7-36", "Physical Therapy", stringPtr("IAB7")},
			{"IAB7-37", "Psychology/Psychiatry", stringPtr("IAB7")},
			{"IAB7-38", "Senior Health", stringPtr("IAB7")},
			{"IAB7-39", "Sexuality", stringPtr("IAB7")},
			{"IAB7-40", "Sleep Disorders", stringPtr("IAB7")},
			{"IAB7-41", "Smoking Cessation", stringPtr("IAB7")},
			{"IAB7-42", "Substance Abuse", stringPtr("IAB7")},
			{"IAB7-43", "Thyroid Disease", stringPtr("IAB7")},
			{"IAB7-44", "Weight Loss", stringPtr("IAB7")},
			{"IAB7-45", "Women’s Health", stringPtr("IAB7")},

			// ---------------- IAB8 ----------------
			{"IAB8", "Food & Drink", stringPtr("IAB")},
			{"IAB8-1", "American Cuisine", stringPtr("IAB8")},
			{"IAB8-2", "Barbecues & Grilling", stringPtr("IAB8")},
			{"IAB8-3", "Cajun/Creole", stringPtr("IAB8")},
			{"IAB8-4", "Chinese Cuisine", stringPtr("IAB8")},
			{"IAB8-5", "Cocktails/Beer", stringPtr("IAB8")},
			{"IAB8-6", "Coffee/Tea", stringPtr("IAB8")},
			{"IAB8-7", "Cuisine-Specific", stringPtr("IAB8")},
			{"IAB8-8", "Desserts & Baking", stringPtr("IAB8")},
			{"IAB8-9", "Dining Out", stringPtr("IAB8")},
			{"IAB8-10", "Food Allergies", stringPtr("IAB8")},
			{"IAB8-11", "French Cuisine", stringPtr("IAB8")},
			{"IAB8-12", "Health/Lowfat Cooking", stringPtr("IAB8")},
			{"IAB8-13", "Italian Cuisine", stringPtr("IAB8")},
			{"IAB8-14", "Japanese Cuisine", stringPtr("IAB8")},
			{"IAB8-15", "Mexican Cuisine", stringPtr("IAB8")},
			{"IAB8-16", "Vegan", stringPtr("IAB8")},
			{"IAB8-17", "Vegetarian", stringPtr("IAB8")},
			{"IAB8-18", "Wine", stringPtr("IAB8")},

			// ---------------- IAB9 ----------------
			{"IAB9", "Hobbies & Interests", stringPtr("IAB")},
			{"IAB9-1", "Art/Technology", stringPtr("IAB9")},
			{"IAB9-2", "Arts & Crafts", stringPtr("IAB9")},
			{"IAB9-3", "Beadwork", stringPtr("IAB9")},
			{"IAB9-4", "Birdwatching", stringPtr("IAB9")},
			{"IAB9-5", "Board Games/Puzzles", stringPtr("IAB9")},
			{"IAB9-6", "Candle & Soap Making", stringPtr("IAB9")},
			{"IAB9-7", "Card Games", stringPtr("IAB9")},
			{"IAB9-8", "Chess", stringPtr("IAB9")},
			{"IAB9-9", "Cigars", stringPtr("IAB9")},
			{"IAB9-10", "Collecting", stringPtr("IAB9")},
			{"IAB9-11", "Comic Books", stringPtr("IAB9")},
			{"IAB9-12", "Drawing/Sketching", stringPtr("IAB9")},
			{"IAB9-13", "Freelance Writing", stringPtr("IAB9")},
			{"IAB9-14", "Genealogy", stringPtr("IAB9")},
			{"IAB9-15", "Getting Published", stringPtr("IAB9")},
			{"IAB9-16", "Guitar", stringPtr("IAB9")},
			{"IAB9-17", "Home Recording", stringPtr("IAB9")},
			{"IAB9-18", "Investors & Patents", stringPtr("IAB9")},
			{"IAB9-19", "Jewelry Making", stringPtr("IAB9")},
			{"IAB9-20", "Magic & Illusion", stringPtr("IAB9")},
			{"IAB9-21", "Needlework", stringPtr("IAB9")},
			{"IAB9-22", "Painting", stringPtr("IAB9")},
			{"IAB9-23", "Photography", stringPtr("IAB9")},
			{"IAB9-24", "Radio", stringPtr("IAB9")},
			{"IAB9-25", "Roleplaying Games", stringPtr("IAB9")},
			{"IAB9-26", "Sci-Fi & Fantasy", stringPtr("IAB9")},
			{"IAB9-27", "Scrapbooking", stringPtr("IAB9")},
			{"IAB9-28", "Screenwriting", stringPtr("IAB9")},
			{"IAB9-29", "Stamps & Coins", stringPtr("IAB9")},
			{"IAB9-30", "Video & Computer Games", stringPtr("IAB9")},
			{"IAB9-31", "Woodworking", stringPtr("IAB9")},

			// ---------------- IAB10 ----------------
			{"IAB10", "Home & Garden", stringPtr("IAB")},
			{"IAB10-1", "Appliances", stringPtr("IAB10")},
			{"IAB10-2", "Entertaining", stringPtr("IAB10")},
			{"IAB10-3", "Environmental Safety", stringPtr("IAB10")},
			{"IAB10-4", "Gardening", stringPtr("IAB10")},
			{"IAB10-5", "Home Repair", stringPtr("IAB10")},
			{"IAB10-6", "Home Theater", stringPtr("IAB10")},
			{"IAB10-7", "Interior Decorating", stringPtr("IAB10")},
			{"IAB10-8", "Landscaping", stringPtr("IAB10")},
			{"IAB10-9", "Remodeling & Construction", stringPtr("IAB10")},

			// ---------------- IAB11 ----------------
			{"IAB11", "Law, Gov’t & Politics", stringPtr("IAB")},
			{"IAB11-1", "Immigration", stringPtr("IAB11")},
			{"IAB11-2", "Legal Issues", stringPtr("IAB11")},
			{"IAB11-3", "U.S. Government Resources", stringPtr("IAB11")},
			{"IAB11-4", "Politics", stringPtr("IAB11")},
			{"IAB11-5", "Commentary", stringPtr("IAB11")},

			// ---------------- IAB12 ----------------
			{"IAB12", "News", stringPtr("IAB")},
			{"IAB12-1", "International News", stringPtr("IAB12")},
			{"IAB12-2", "National News", stringPtr("IAB12")},
			{"IAB12-3", "Local News", stringPtr("IAB12")},

			// ---------------- IAB13 ----------------
			{"IAB13", "Personal Finance", stringPtr("IAB")},
			{"IAB13-1", "Beginning Investing", stringPtr("IAB13")},
			{"IAB13-2", "Credit/Debt & Loans", stringPtr("IAB13")},
			{"IAB13-3", "Financial News", stringPtr("IAB13")},
			{"IAB13-4", "Financial Planning", stringPtr("IAB13")},
			{"IAB13-5", "Hedge Fund", stringPtr("IAB13")},
			{"IAB13-6", "Insurance", stringPtr("IAB13")},
			{"IAB13-7", "Investing", stringPtr("IAB13")},
			{"IAB13-8", "Mutual Funds", stringPtr("IAB13")},
			{"IAB13-9", "Options", stringPtr("IAB13")},
			{"IAB13-10", "Retirement Planning", stringPtr("IAB13")},
			{"IAB13-11", "Stocks", stringPtr("IAB13")},
			{"IAB13-12", "Tax Planning", stringPtr("IAB13")},

			// ---------------- IAB14 ----------------
			{"IAB14", "Society", stringPtr("IAB")},
			{"IAB14-1", "Dating", stringPtr("IAB14")},
			{"IAB14-2", "Divorce Support", stringPtr("IAB14")},
			{"IAB14-3", "Gay Life", stringPtr("IAB14")},
			{"IAB14-4", "Marriage", stringPtr("IAB14")},
			{"IAB14-5", "Senior Living", stringPtr("IAB14")},
			{"IAB14-6", "Teens", stringPtr("IAB14")},
			{"IAB14-7", "Weddings", stringPtr("IAB14")},
			{"IAB14-8", "Ethnic Specific", stringPtr("IAB14")},

			// ---------------- IAB15 ----------------
			{"IAB15", "Science", stringPtr("IAB")},
			{"IAB15-1", "Astrology", stringPtr("IAB15")},
			{"IAB15-2", "Biology", stringPtr("IAB15")},
			{"IAB15-3", "Chemistry", stringPtr("IAB15")},
			{"IAB15-4", "Geology", stringPtr("IAB15")},
			{"IAB15-5", "Paranormal Phenomena", stringPtr("IAB15")},
			{"IAB15-6", "Physics", stringPtr("IAB15")},
			{"IAB15-7", "Space/Astronomy", stringPtr("IAB15")},
			{"IAB15-8", "Geography", stringPtr("IAB15")},
			{"IAB15-9", "Botany", stringPtr("IAB15")},
			{"IAB15-10", "Weather", stringPtr("IAB15")},

			// ---------------- IAB16 ----------------
			{"IAB16", "Pets", stringPtr("IAB")},
			{"IAB16-1", "Aquariums", stringPtr("IAB16")},
			{"IAB16-2", "Birds", stringPtr("IAB16")},
			{"IAB16-3", "Cats", stringPtr("IAB16")},
			{"IAB16-4", "Dogs", stringPtr("IAB16")},
			{"IAB16-5", "Large Animals", stringPtr("IAB16")},
			{"IAB16-6", "Reptiles", stringPtr("IAB16")},
			{"IAB16-7", "Veterinary Medicine", stringPtr("IAB16")},

			// ---------------- IAB17 ----------------
			{"IAB17", "Sports", stringPtr("IAB")},
			{"IAB17-1", "Auto Racing", stringPtr("IAB17")},
			{"IAB17-2", "Baseball", stringPtr("IAB17")},
			{"IAB17-3", "Bicycling", stringPtr("IAB17")},
			{"IAB17-4", "Bodybuilding", stringPtr("IAB17")},
			{"IAB17-5", "Boxing", stringPtr("IAB17")},
			{"IAB17-6", "Canoeing/Kayaking", stringPtr("IAB17")},
			{"IAB17-7", "Cheerleading", stringPtr("IAB17")},
			{"IAB17-8", "Climbing", stringPtr("IAB17")},
			{"IAB17-9", "Cricket", stringPtr("IAB17")},
			{"IAB17-10", "Figure Skating", stringPtr("IAB17")},
			{"IAB17-11", "Fly Fishing", stringPtr("IAB17")},
			{"IAB17-12", "Football", stringPtr("IAB17")},
			{"IAB17-13", "Freshwater Fishing", stringPtr("IAB17")},
			{"IAB17-14", "Game & Fish", stringPtr("IAB17")},
			{"IAB17-15", "Golf", stringPtr("IAB17")},
			{"IAB17-16", "Horse Racing", stringPtr("IAB17")},
			{"IAB17-17", "Horses", stringPtr("IAB17")},
			{"IAB17-18", "Hunting/Shooting", stringPtr("IAB17")},
			{"IAB17-19", "Inline Skating", stringPtr("IAB17")},
			{"IAB17-20", "Martial Arts", stringPtr("IAB17")},
			{"IAB17-21", "Mountain Biking", stringPtr("IAB17")},
			{"IAB17-22", "NASCAR Racing", stringPtr("IAB17")},
			{"IAB17-23", "Olympics", stringPtr("IAB17")},
			{"IAB17-24", "Paintball", stringPtr("IAB17")},
			{"IAB17-25", "Power & Motorcycles", stringPtr("IAB17")},
			{"IAB17-26", "Pro Basketball", stringPtr("IAB17")},
			{"IAB17-27", "Pro Ice Hockey", stringPtr("IAB17")},
			{"IAB17-28", "Rodeo", stringPtr("IAB17")},
			{"IAB17-29", "Rugby", stringPtr("IAB17")},
			{"IAB17-30", "Running/Jogging", stringPtr("IAB17")},
			{"IAB17-31", "Sailing", stringPtr("IAB17")},
			{"IAB17-32", "Saltwater Fishing", stringPtr("IAB17")},
			{"IAB17-33", "Scuba Diving", stringPtr("IAB17")},
			{"IAB17-34", "Skateboarding", stringPtr("IAB17")},
			{"IAB17-35", "Skiing", stringPtr("IAB17")},
			{"IAB17-36", "Snowboarding", stringPtr("IAB17")},
			{"IAB17-37", "Surfing/Bodyboarding", stringPtr("IAB17")},
			{"IAB17-38", "Swimming", stringPtr("IAB17")},
			{"IAB17-39", "Table Tennis/Ping-Pong", stringPtr("IAB17")},
			{"IAB17-40", "Tennis", stringPtr("IAB17")},
			{"IAB17-41", "Volleyball", stringPtr("IAB17")},
			{"IAB17-42", "Walking", stringPtr("IAB17")},
			{"IAB17-43", "Waterski/Wakeboard", stringPtr("IAB17")},
			{"IAB17-44", "World Soccer", stringPtr("IAB17")},

			// ---------------- IAB18 ----------------
			{"IAB18", "Style & Fashion", stringPtr("IAB")},
			{"IAB18-1", "Beauty", stringPtr("IAB18")},
			{"IAB18-2", "Body Art", stringPtr("IAB18")},
			{"IAB18-3", "Fashion", stringPtr("IAB18")},
			{"IAB18-4", "Jewelry", stringPtr("IAB18")},
			{"IAB18-5", "Clothing", stringPtr("IAB18")},
			{"IAB18-6", "Accessories", stringPtr("IAB18")},

			// ---------------- IAB19 ----------------
			{"IAB19", "Technology & Computing", stringPtr("IAB")},
			{"IAB19-1", "3-D Graphics", stringPtr("IAB19")},
			{"IAB19-2", "Animation", stringPtr("IAB19")},
			{"IAB19-3", "Antivirus Software", stringPtr("IAB19")},
			{"IAB19-4", "C/C++", stringPtr("IAB19")},
			{"IAB19-5", "Cameras & Camcorders", stringPtr("IAB19")},
			{"IAB19-6", "Cell Phones", stringPtr("IAB19")},
			{"IAB19-7", "Computer Certification", stringPtr("IAB19")},
			{"IAB19-8", "Computer Networking", stringPtr("IAB19")},
			{"IAB19-9", "Computer Peripherals", stringPtr("IAB19")},
			{"IAB19-10", "Computer Reviews", stringPtr("IAB19")},
			{"IAB19-11", "Data Centers", stringPtr("IAB19")},
			{"IAB19-12", "Databases", stringPtr("IAB19")},
			{"IAB19-13", "Desktop Publishing", stringPtr("IAB19")},
			{"IAB19-14", "Desktop Video", stringPtr("IAB19")},
			{"IAB19-15", "Email", stringPtr("IAB19")},
			{"IAB19-16", "Graphics Software", stringPtr("IAB19")},
			{"IAB19-17", "Home Video/DVD", stringPtr("IAB19")},
			{"IAB19-18", "Internet Technology", stringPtr("IAB19")},
			{"IAB19-19", "Java", stringPtr("IAB19")},
			{"IAB19-20", "JavaScript", stringPtr("IAB19")},
			{"IAB19-21", "Mac Support", stringPtr("IAB19")},
			{"IAB19-22", "MP3/MIDI", stringPtr("IAB19")},
			{"IAB19-23", "Net Conferencing", stringPtr("IAB19")},
			{"IAB19-24", "Net for Beginners", stringPtr("IAB19")},
			{"IAB19-25", "Network Security", stringPtr("IAB19")},
			{"IAB19-26", "Palmtops/PDAs", stringPtr("IAB19")},
			{"IAB19-27", "PC Support", stringPtr("IAB19")},
			{"IAB19-28", "Portable", stringPtr("IAB19")},
			{"IAB19-29", "Entertainment", stringPtr("IAB19")},
			{"IAB19-30", "Shareware/Freeware", stringPtr("IAB19")},
			{"IAB19-31", "Unix", stringPtr("IAB19")},
			{"IAB19-32", "Visual Basic", stringPtr("IAB19")},
			{"IAB19-33", "Web Clip Art", stringPtr("IAB19")},
			{"IAB19-34", "Web Design/HTML", stringPtr("IAB19")},
			{"IAB19-35", "Web Search", stringPtr("IAB19")},
			{"IAB19-36", "Windows", stringPtr("IAB19")},

			// ---------------- IAB20 ----------------
			{"IAB20", "Travel", stringPtr("IAB")},
			{"IAB20-1", "Adventure Travel", stringPtr("IAB20")},
			{"IAB20-2", "Africa", stringPtr("IAB20")},
			{"IAB20-3", "Air Travel", stringPtr("IAB20")},
			{"IAB20-4", "Australia & New Zealand", stringPtr("IAB20")},
			{"IAB20-5", "Bed & Breakfasts", stringPtr("IAB20")},
			{"IAB20-6", "Budget Travel", stringPtr("IAB20")},
			{"IAB20-7", "Business Travel", stringPtr("IAB20")},
			{"IAB20-8", "By US Locale", stringPtr("IAB20")},
			{"IAB20-9", "Camping", stringPtr("IAB20")},
			{"IAB20-10", "Canada", stringPtr("IAB20")},
			{"IAB20-11", "Caribbean", stringPtr("IAB20")},
			{"IAB20-12", "Cruises", stringPtr("IAB20")},
			{"IAB20-13", "Eastern Europe", stringPtr("IAB20")},
			{"IAB20-14", "Europe", stringPtr("IAB20")},
			{"IAB20-15", "France", stringPtr("IAB20")},
			{"IAB20-16", "Greece", stringPtr("IAB20")},
			{"IAB20-17", "Honeymoons/Getaways", stringPtr("IAB20")},
			{"IAB20-18", "Hotels", stringPtr("IAB20")},
			{"IAB20-19", "Italy", stringPtr("IAB20")},
			{"IAB20-20", "Japan", stringPtr("IAB20")},
			{"IAB20-21", "Mexico & Central America", stringPtr("IAB20")},
			{"IAB20-22", "National Parks", stringPtr("IAB20")},
			{"IAB20-23", "South America", stringPtr("IAB20")},
			{"IAB20-24", "Spas", stringPtr("IAB20")},
			{"IAB20-25", "Theme Parks", stringPtr("IAB20")},
			{"IAB20-26", "Traveling with Kids", stringPtr("IAB20")},
			{"IAB20-27", "United Kingdom", stringPtr("IAB20")},

			// ---------------- IAB21 ----------------
			{"IAB21", "Real Estate", stringPtr("IAB")},
			{"IAB21-1", "Apartments", stringPtr("IAB21")},
			{"IAB21-2", "Architects", stringPtr("IAB21")},
			{"IAB21-3", "Buying/Selling Homes", stringPtr("IAB21")},

			// ---------------- IAB22 ----------------
			{"IAB22", "Shopping", stringPtr("IAB")},
			{"IAB22-1", "Contests & Freebies", stringPtr("IAB22")},
			{"IAB22-2", "Couponing", stringPtr("IAB22")},
			{"IAB22-3", "Comparison", stringPtr("IAB22")},
			{"IAB22-4", "Engines", stringPtr("IAB22")},

			// ---------------- IAB23 ----------------
			{"IAB23", "Religion & Spirituality", stringPtr("IAB")},
			{"IAB23-1", "Alternative Religions", stringPtr("IAB23")},
			{"IAB23-2", "Atheism/Agnosticism", stringPtr("IAB23")},
			{"IAB23-3", "Buddhism", stringPtr("IAB23")},
			{"IAB23-4", "Catholicism", stringPtr("IAB23")},
			{"IAB23-5", "Christianity", stringPtr("IAB23")},
			{"IAB23-6", "Hinduism", stringPtr("IAB23")},
			{"IAB23-7", "Islam", stringPtr("IAB23")},
			{"IAB23-8", "Judaism", stringPtr("IAB23")},
			{"IAB23-9", "Latter-Day Saints", stringPtr("IAB23")},
			{"IAB23-10", "Pagan/Wiccan", stringPtr("IAB23")},

			// ---------------- IAB24 ----------------
			{"IAB24", "Uncategorized", stringPtr("IAB")},

			// ---------------- IAB25 ----------------
			{"IAB25", "Non-Standard Content", stringPtr("IAB")},
			{"IAB25-1", "Unmoderated UGC", stringPtr("IAB25")},
			{"IAB25-2", "Extreme Graphic/Explicit Violence", stringPtr("IAB25")},
			{"IAB25-3", "Pornography", stringPtr("IAB25")},
			{"IAB25-4", "Profane Content", stringPtr("IAB25")},
			{"IAB25-5", "Hate Content", stringPtr("IAB25")},
			{"IAB25-6", "Under Construction", stringPtr("IAB25")},
			{"IAB25-7", "Incentivized", stringPtr("IAB25")},

			// ---------------- IAB26 ----------------
			{"IAB26", "Illegal Content", stringPtr("IAB")},
			{"IAB26-1", "Illegal Content", stringPtr("IAB26")},
			{"IAB26-2", "Warez", stringPtr("IAB26")},
			{"IAB26-3", "Spyware/Malware", stringPtr("IAB26")},
			{"IAB26-4", "Copyright Infringement", stringPtr("IAB26")},

			// ---------------- Adult / Mature Content ----------------
			{"SC-AMC", "Adult / Mature Content", stringPtr("SC")},
			{"SC-AMC-1", "Abortion", stringPtr("SC-AMC")},
			{"SC-AMC-2", "Advocacy Organizations", stringPtr("SC-AMC")},
			{"SC-AMC-3", "Alcohol", stringPtr("SC-AMC")},
			{"SC-AMC-4", "Alternative Beliefs", stringPtr("SC-AMC")},
			{"SC-AMC-5", "Dating", stringPtr("SC-AMC")},
			{"SC-AMC-6", "Gambling", stringPtr("SC-AMC")},
			{"SC-AMC-7", "Lingerie and Swimsuit", stringPtr("SC-AMC")},
			{"SC-AMC-8", "Marijuana", stringPtr("SC-AMC")},
			{"SC-AMC-9", "Nudity and Risque", stringPtr("SC-AMC")},
			{"SC-AMC-10", "Other Adult Materials", stringPtr("SC-AMC")},
			{"SC-AMC-11", "Pornography", stringPtr("SC-AMC")},
			{"SC-AMC-12", "Sex Education", stringPtr("SC-AMC")},
			{"SC-AMC-13", "Sports Hunting and War Games", stringPtr("SC-AMC")},
			{"SC-AMC-14", "Tobacco", stringPtr("SC-AMC")},
			{"SC-AMC-15", "Weapons (Sales)", stringPtr("SC-AMC")},

			// ---------------- Bandwidth Consuming ----------------
			{"SC-BC", "Bandwidth Consuming", stringPtr("SC")},
			{"SC-BC-1", "File Sharing and Storage", stringPtr("SC-BC")},
			{"SC-BC-2", "Freeware and Software Downloads", stringPtr("SC-BC")},
			{"SC-BC-3", "Internet Radio and TV", stringPtr("SC-BC")},
			{"SC-BC-4", "Internet Telephony", stringPtr("SC-BC")},
			{"SC-BC-5", "Peer-to-peer File Sharing", stringPtr("SC-BC")},
			{"SC-BC-6", "Streaming Media and Download", stringPtr("SC-BC")},

			// ---------------- General Interest - Business ----------------
			{"SC-GIB", "General Interest - Business", stringPtr("SC")},
			{"SC-GIB-1", "Armed Forces", stringPtr("SC-GIB")},
			{"SC-GIB-2", "Artificial Intelligence Technology", stringPtr("SC-GIB")},
			{"SC-GIB-3", "Business", stringPtr("SC-GIB")},
			{"SC-GIB-4", "Charitable Organizations", stringPtr("SC-GIB")},
			{"SC-GIB-5", "Cryptocurrency", stringPtr("SC-GIB")},
			{"SC-GIB-6", "Finance and Banking", stringPtr("SC-GIB")},
			{"SC-GIB-7", "General Organizations", stringPtr("SC-GIB")},
			{"SC-GIB-8", "Government and Legal Organizations", stringPtr("SC-GIB")},
			{"SC-GIB-9", "Information Technology", stringPtr("SC-GIB")},
			{"SC-GIB-10", "Information and Computer Security", stringPtr("SC-GIB")},
			{"SC-GIB-11", "Online Meeting", stringPtr("SC-GIB")},
			{"SC-GIB-12", "Remote Access", stringPtr("SC-GIB")},
			{"SC-GIB-13", "Search Engines and Portals", stringPtr("SC-GIB")},
			{"SC-GIB-14", "Secure Websites", stringPtr("SC-GIB")},
			{"SC-GIB-15", "URL Shortening", stringPtr("SC-GIB")},
			{"SC-GIB-16", "Web Analytics", stringPtr("SC-GIB")},
			{"SC-GIB-17", "Web Hosting", stringPtr("SC-GIB")},
			{"SC-GIB-18", "Web-based Applications", stringPtr("SC-GIB")},

			// ---------------- General Interest - Personal ----------------
			{"SC-GIP", "General Interest - Personal", stringPtr("SC")},
			{"SC-GIP-1", "Advertising", stringPtr("SC-GIP")},
			{"SC-GIP-2", "Arts and Culture", stringPtr("SC-GIP")},
			{"SC-GIP-3", "Auction", stringPtr("SC-GIP")},
			{"SC-GIP-4", "Brokerage and Trading", stringPtr("SC-GIP")},
			{"SC-GIP-5", "Child Education", stringPtr("SC-GIP")},
			{"SC-GIP-6", "Content Servers", stringPtr("SC-GIP")},
			{"SC-GIP-7", "Digital Postcards", stringPtr("SC-GIP")},
			{"SC-GIP-8", "Domain Parking", stringPtr("SC-GIP")},
			{"SC-GIP-9", "Dynamic Content", stringPtr("SC-GIP")},
			{"SC-GIP-10", "Education", stringPtr("SC-GIP")},
			{"SC-GIP-11", "Entertainment", stringPtr("SC-GIP")},
			{"SC-GIP-12", "Folklore", stringPtr("SC-GIP")},
			{"SC-GIP-13", "Games", stringPtr("SC-GIP")},
			{"SC-GIP-14", "Global Religion", stringPtr("SC-GIP")},
			{"SC-GIP-15", "Health and Wellness", stringPtr("SC-GIP")},
			{"SC-GIP-16", "Instant Messaging", stringPtr("SC-GIP")},
			{"SC-GIP-17", "Job Search", stringPtr("SC-GIP")},
			{"SC-GIP-18", "Meaningless Content", stringPtr("SC-GIP")},
			{"SC-GIP-19", "Medicine", stringPtr("SC-GIP")},
			{"SC-GIP-20", "News and Media", stringPtr("SC-GIP")},
			{"SC-GIP-21", "Newsgroups and Message Boards", stringPtr("SC-GIP")},
			{"SC-GIP-22", "Personal Privacy", stringPtr("SC-GIP")},
			{"SC-GIP-23", "Personal Vehicles", stringPtr("SC-GIP")},
			{"SC-GIP-24", "Personal Websites and Blogs", stringPtr("SC-GIP")},
			{"SC-GIP-25", "Political Organizations", stringPtr("SC-GIP")},
			{"SC-GIP-26", "Real Estate", stringPtr("SC-GIP")},
			{"SC-GIP-27", "Reference", stringPtr("SC-GIP")},
			{"SC-GIP-28", "Restaurant and Dining", stringPtr("SC-GIP")},
			{"SC-GIP-29", "Shopping", stringPtr("SC-GIP")},
			{"SC-GIP-30", "Social Networking", stringPtr("SC-GIP")},
			{"SC-GIP-31", "Society and Lifestyles", stringPtr("SC-GIP")},
			{"SC-GIP-32", "Sports", stringPtr("SC-GIP")},
			{"SC-GIP-33", "Travel", stringPtr("SC-GIP")},
			{"SC-GIP-34", "Web Chat", stringPtr("SC-GIP")},
			{"SC-GIP-35", "Web-based Email", stringPtr("SC-GIP")},

			// ---------------- Potentially Liable ----------------
			{"SC-PL", "Potentially Liable", stringPtr("SC")},
			{"SC-PL-1", "Child Sexual Abuse", stringPtr("SC-PL")},
			{"SC-PL-2", "Crypto Mining", stringPtr("SC-PL")},
			{"SC-PL-3", "Discrimination", stringPtr("SC-PL")},
			{"SC-PL-4", "Drug Abuse", stringPtr("SC-PL")},
			{"SC-PL-5", "Explicit Violence", stringPtr("SC-PL")},
			{"SC-PL-6", "Extremist Groups", stringPtr("SC-PL")},
			{"SC-PL-7", "Hacking", stringPtr("SC-PL")},
			{"SC-PL-8", "Illegal or Unethical", stringPtr("SC-PL")},
			{"SC-PL-9", "Plagiarism", stringPtr("SC-PL")},
			{"SC-PL-10", "Potentially Unwanted Program", stringPtr("SC-PL")},
			{"SC-PL-11", "Proxy Avoidance", stringPtr("SC-PL")},
			{"SC-PL-12", "Terrorism", stringPtr("SC-PL")},

			// ---------------- Security Risk ----------------
			{"SC-SR", "Security Risk", stringPtr("SC")},
			{"SC-SR-1", "Dynamic DNS", stringPtr("SC-SR")},
			{"SC-SR-2", "Malicious Websites", stringPtr("SC-SR")},
			{"SC-SR-3", "Newly Observed Domain", stringPtr("SC-SR")},
			{"SC-SR-4", "Newly Registered Domain", stringPtr("SC-SR")},
			{"SC-SR-5", "Phishing", stringPtr("SC-SR")},
			{"SC-SR-6", "Spam URLs", stringPtr("SC-SR")},

			// ---------------- Unrated ----------------
			{"SC-UR", "Unrated", stringPtr("SC")},
			{"SC-UR-1", "Not Rated", stringPtr("SC-UR")},
		}

		for _, s := range seed {
			re.db.CreateDNSCategory(&db.DNSCategory{
				CategoryId:       s.ID,
				CategoryName:     s.Name,
				ParentCategoryId: s.Parent,
				Enabled:          true,
			})
		}

		re.db.CreateDNSCategory(&db.DNSCategory{
			CategoryId:       "fakenews",
			CategoryName:     "Fake News",
			ParentCategoryId: nil,
			Enabled:          true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "sb-fakenews",
			CategoryId:  "fakenews",
			RuleSetName: "Steven Black FakeNews",
			Source:      "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-only/hosts",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSCategory(&db.DNSCategory{
			CategoryId:   "gambling",
			CategoryName: "Gambling",
			Enabled:      true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "sb-gambling",
			CategoryId:  "gambling",
			RuleSetName: "Steven Black Gambling",
			Source:      "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling-only/hosts",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSCategory(&db.DNSCategory{
			CategoryId:   "adult",
			CategoryName: "Adult content",
			Enabled:      true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "sb-porn",
			CategoryId:  "adult",
			RuleSetName: "Steven Black Pornography",
			Source:      "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSCategory(&db.DNSCategory{
			CategoryId:   "social",
			CategoryName: "Social Media",
			Enabled:      true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "sb-social",
			CategoryId:  "social",
			RuleSetName: "Steven Black Social Media",
			Source:      "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/social-only/hosts",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSCategory(&db.DNSCategory{
			CategoryId:   "malicious",
			CategoryName: "Malicious sites",
			Enabled:      true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-scams",
			CategoryId:  "malicious",
			RuleSetName: "HaGeZi's Fake DNS Blocklist",
			Description: "Protects against internet scams, traps & fakes! Blocks fake stores, -streaming, rip-offs, cost traps and co.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/fake-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled: true,
		})

		re.db.CreateDNSCategory(&db.DNSCategory{
			CategoryId:   "ads",
			CategoryName: "Ads & popups",
			Enabled:      true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-ads",
			CategoryId:  "ads",
			RuleSetName: "HaGeZi's Pop-Up Ads DNS Blocklist",
			Description: "Blocks annoying and malicious pop-up ads.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/popupads-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSCategory(&db.DNSCategory{
			CategoryId:   "ads",
			CategoryName: "Ads & popups",
			Enabled:      true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-ads",
			CategoryId:  "ads",
			RuleSetName: "HaGeZi's Pop-Up Ads DNS Blocklist",
			Description: "Blocks annoying and malicious pop-up ads.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/popupads-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSCategory(&db.DNSCategory{
			CategoryId:   "threats",
			CategoryName: "Threats",
			Enabled:      true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-tif",
			CategoryId:  "malicious",
			RuleSetName: "HaGeZi's Pop-Up Ads DNS Blocklist",
			Description: "Increases security significantly! Blocks Malware, Cryptojacking, Spam, Scam and Phishing.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSCategory(&db.DNSCategory{
			CategoryId:   "nrd",
			CategoryName: "Newly Registered Domains",
			Enabled:      true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-nrd7",
			CategoryId:  "nrd",
			RuleSetName: "Newly Registered Domains (NRD) - Last 7 days",
			Description: "Domains from 7 days ago to yesterday (the last day)",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nrd7.txt",
			Schedule:    "0 23 * * *",

			Enabled:  false,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-nrd8-14",
			CategoryId:  "nrd",
			RuleSetName: "Newly Registered Domains (NRD) - 8 to 14 days",
			Description: "Domains from 14 days ago to 8 days ago",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nrd14-8.txt",
			Schedule:    "0 23 * * *",

			Enabled:  false,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-nrd15-21",
			CategoryId:  "nrd",
			RuleSetName: "Newly Registered Domains (NRD) - 15 to 21 days",
			Description: "Domains from 21 days ago to 15 days ago",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nrd21-15.txt",
			Schedule:    "0 23 * * *",

			Enabled:  false,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-nrd22-28",
			CategoryId:  "nrd",
			RuleSetName: "Newly Registered Domains (NRD) - 22 to 28 days",
			Description: "Domains from 28 days ago to 22 days ago",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nrd28-22.txt",
			Schedule:    "0 23 * * *",

			Enabled:  false,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-nrd29-35",
			CategoryId:  "nrd",
			RuleSetName: "Newly Registered Domains (NRD) - 29 to 35 days",
			Description: "Domains from 35 days ago to 29 days ago",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/nrd35-29.txt",
			Schedule:    "0 23 * * *",

			Enabled:  false,
			External: true,
		})

		re.db.CreateDNSCategory(&db.DNSCategory{
			CategoryId:   "bypass",
			CategoryName: "Bypassing services",
			Enabled:      true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-network-bypass",
			CategoryId:  "bypass",
			RuleSetName: "HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass DNS Blocklist",
			Description: "Prevent methods to bypass your DNS, blocks encrypted DNS, VPN, TOR, Proxies.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/doh-vpn-proxy-bypass-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-safesearch-bypass",
			CategoryId:  "bypass",
			RuleSetName: "HaGeZi's safesearch not supported DNS Blocklist",
			Description: "Prevents the use of search engines that do not support safesearch.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nosafesearch-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-safesearch-bypass",
			CategoryId:  "bypass",
			RuleSetName: "HaGeZi's safesearch not supported DNS Blocklist",
			Description: "Prevents the use of search engines that do not support safesearch.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nosafesearch-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-badware",
			CategoryId:  "malicious",
			RuleSetName: "HaGeZi's Badware Hoster DNS Blocklist",
			Description: "Blocks known hosters that also host badware via user content to prevent the use of these hosters for malicious purposes.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/dyndns-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-tlds",
			CategoryId:  "malicious",
			RuleSetName: "HaGeZi's The World's Most Abused TLDs - Aggressive",
			Description: "The Top Most Abused Top Level Domains",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/spam-tlds-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSCategory(&db.DNSCategory{
			CategoryId:   "urlshortner",
			CategoryName: "URL Shortner Services",
			Enabled:      true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-urlshortner",
			CategoryId:  "urlshortner",
			RuleSetName: "HaGeZi's Blocklist URL Shortener",
			Description: "This list blocks url shortener.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/urlshortener-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSCategory(&db.DNSCategory{
			CategoryId:   "piracy",
			CategoryName: "Pirated content",
			Enabled:      true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-piracy",
			CategoryId:  "piracy",
			RuleSetName: "HaGeZi's Anti-Piracy DNS Blocklist",
			Description: "Blocks websites and services that are mainly used for illegal distribution of copyrighted content.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/anti.piracy-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSCategory(&db.DNSCategory{
			CategoryId:   "gambling",
			CategoryName: "Gambling",
			Enabled:      true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-gambling",
			CategoryId:  "gambling",
			RuleSetName: "HaGeZi's Gambling DNS Blocklist",
			Description: "Blocks gambling content.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/gambling-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-social",
			CategoryId:  "social",
			RuleSetName: "HaGeZi's Social Networks DNS Blocklist",
			Description: "Blocks access to social networks (Facebook, Instagram, TikTok, X (formerly Twitter), Snapchat, ...)",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/social-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-nsfw",
			CategoryId:  "adult",
			RuleSetName: "HaGeZi's NSFW DNS Blocklist",
			Description: "Blocks adult content.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nsfw-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSCategory(&db.DNSCategory{
			CategoryId:   "tracker",
			CategoryName: "Trackers",
			Enabled:      true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-amazon",
			CategoryId:  "tracker",
			RuleSetName: "HaGeZi's Amazon Tracker DNS Blocklist",
			Description: "Blocks Amazon native broadband tracker that track your activity.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.amazon-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-apple",
			CategoryId:  "tracker",
			RuleSetName: "HaGeZi's Apple Tracker DNS Blocklist",
			Description: "Blocks Apple native broadband tracker that track your activity.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.apple-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-huawei",
			CategoryId:  "tracker",
			RuleSetName: "HaGeZi's Huawei Tracker DNS Blocklist",
			Description: "Blocks Hauwei native broadband tracker that track your activity.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.huawei-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-winoffice",
			CategoryId:  "tracker",
			RuleSetName: "HaGeZi's Windows/Office Tracker DNS Blocklist",
			Description: "Blocks Windows/Office native broadband tracker that track your activity.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.winoffice-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-tiktok",
			CategoryId:  "tracker",
			RuleSetName: "HaGeZi's Tiktok Extended Tracker DNS Blocklist",
			Description: "Blocks Tiktok Extended native broadband tracker that track your activity.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.tiktok.extended-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-lgwebos",
			CategoryId:  "tracker",
			RuleSetName: "HaGeZi's LG webOS Tracker DNS Blocklist",
			Description: "Blocks LG webOS native broadband tracker that track your activity.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.lgwebos-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "hagezi-roku",
			CategoryId:  "tracker",
			RuleSetName: "HaGeZi's Roku Tracker DNS Blocklist",
			Description: "Blocks Roku native broadband tracker that track your activity.",
			Source:      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/native.roku-onlydomains.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-abuse",
			CategoryId:  "malicious",
			RuleSetName: "Abuse Block List",
			Description: "Domains involved in abuse",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/abuse-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-ads",
			CategoryId:  "ads",
			RuleSetName: "Ads Block List",
			Description: "Ad serving domains",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/ads-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-crypto",
			CategoryId:  "malicious",
			RuleSetName: "Crypto Block List",
			Description: "Cryptocurrency mining and scams",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/crypto-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-crypto",
			CategoryId:  "malicious",
			RuleSetName: "Crypto Block List",
			Description: "Cryptocurrency mining and scams",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/crypto-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSCategory(&db.DNSCategory{
			CategoryId:   "drugs",
			CategoryName: "Drugs",
			Enabled:      true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-drugs",
			CategoryId:  "drugs",
			RuleSetName: "Drugs Block List",
			Description: "Drug-related domains",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/drugs-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-facebook",
			CategoryId:  "social",
			RuleSetName: "Facebook/Meta Block List",
			Description: "Facebook and Meta domains",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/facebook-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-fraud",
			CategoryId:  "malicious",
			RuleSetName: "Fraud Block List",
			Description: "Fraud and scam domains",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/fraud-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-gambling",
			CategoryId:  "gambling",
			RuleSetName: "Gambling Block List",
			Description: "Gambling sites",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/gambling-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-malware",
			CategoryId:  "malicious",
			RuleSetName: "Malware Block List",
			Description: "Malware distribution domains",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/malware-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-phishing",
			CategoryId:  "malicious",
			RuleSetName: "Phishing Block List",
			Description: "Phishing domains",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/phishing-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-piracy",
			CategoryId:  "piracy",
			RuleSetName: "Piracy Block List",
			Description: "Piracy and illegal streaming",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/piracy-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-porn",
			CategoryId:  "adult",
			RuleSetName: "Porn Block List",
			Description: "Adult content domains",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/porn-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-ransomware",
			CategoryId:  "malicious",
			RuleSetName: "Ransomware Block List",
			Description: "Ransomware C2 and distribution",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/ransomware-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-redirect",
			CategoryId:  "malicious",
			RuleSetName: "Redirect Block List",
			Description: "URL shorteners and redirects",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/redirect-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-scam",
			CategoryId:  "malicious",
			RuleSetName: "Scam Block List",
			Description: "Scam domains",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/scam-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-tiktok",
			CategoryId:  "social",
			RuleSetName: "Tiktok Block List",
			Description: "TikTok domains",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/tiktok-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-torrent",
			CategoryId:  "piracy",
			RuleSetName: "Torrent Block List",
			Description: "Torrent and P2P sites",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/torrent-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-tracker",
			CategoryId:  "tracker",
			RuleSetName: "Tracking Block List",
			Description: "Tracking and analytics",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/tracking-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-twitter",
			CategoryId:  "social",
			RuleSetName: "Twitter Block List",
			Description: "Twitter/X domains",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/twitter-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-vaping",
			CategoryId:  "drugs",
			RuleSetName: "Vaping Block List",
			Description: "Vaping and e-cigarette sites",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/vaping-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

		re.db.CreateDNSRuleSet(&db.DNSRuleSet{
			RuleSetId:   "blocklistproject-whatsapp",
			CategoryId:  "social",
			RuleSetName: "Whatsapp Block List",
			Description: "WhatsApp domains",
			Source:      "https://blocklistproject.github.io/Lists/alt-version/whatsapp-nl.txt",
			Schedule:    "0 23 * * *",

			Enabled:  true,
			External: true,
		})

	}
}

func isValidHostSourceRecord(split []string) bool {
	if len(split) == 0 {
		return false
	}
	if len(split) > 2 {
		return false
	}
	if len(split) == 2 {
		if split[0] != "0.0.0.0" {
			return false
		}
		if split[0] == "0.0.0.0" && split[1] == "0.0.0.0" {
			return false
		}
	}
	return true
}

func (re DNSRulesEngine) UpdateRuleSet(rs db.DNSRuleSet) error {
	if !rs.Enabled {
		return fmt.Errorf("Ruleset %s not enabled", rs.RuleSetName)
	}
	if rs.Source == "" {
		return fmt.Errorf("Ruleset %s source not specified", rs.RuleSetName)
	}

	data, err := getUrlData(rs.Source)
	if err != nil {
		return fmt.Errorf("Unable to fetch ruleset %s: %w", rs.RuleSetName, err)
	}

	var list = make([]string, 0)
	reader := bytes.NewReader(data)
	fileScanner := bufio.NewScanner(reader)
	fileScanner.Split(bufio.ScanLines)
	regex := regexp.MustCompile(`\s+`)
	for fileScanner.Scan() {
		line := strings.TrimSpace(fileScanner.Text())
		if line != "" && line[0] != '#' {
			split := regex.Split(line, -1)
			if isValidHostSourceRecord(split) {
				if len(split) == 2 {
					list = append(list, strings.ToLower(split[1])+".")
				} else if len(split) == 1 {
					list = append(list, strings.ToLower(split[0])+".")
				}
			}
		}
	}
	return re.db.UpdateDNSRules(&rs, &list)
}

type Signal struct {
	Source   string `json:"source"`
	Evidence string `json:"evidence"`
}

type Category struct {
	CategoryID    string   `json:"category_id"`
	Category      string   `json:"category"`
	SubcategoryID *string  `json:"subcategory_id"`
	Subcategory   *string  `json:"subcategory"`
	Confidence    int      `json:"confidence"`
	KeywordsFound []string `json:"keywords_found"`
	Signals       []Signal `json:"signals"`
}

type Response struct {
	URL                       string     `json:"url"`
	PrimaryCategory           string     `json:"primary_category"`
	PrimaryCategoryID         string     `json:"primary_category_id"`
	Categories                []Category `json:"categories"`
	PrimaryCategoryConfidence string     `json:"primary_category_confidence"`
	Title                     string     `json:"title"`
	Description               string     `json:"description"`
	Language                  string     `json:"language"`
	LanguageConfidence        string     `json:"language_confidence"`
	AdultContent              bool       `json:"adult_content"`
	SignalsUsed               int        `json:"signals_used"`
	Cached                    bool       `json:"cached"`
	TotalTimeMS               int        `json:"total_time_ms"`
	CheckedAt                 string     `json:"checked_at"`
}

func getUrlData(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("received invalid http response code " + strconv.Itoa(resp.StatusCode) + "for url " + url)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (re DNSRulesEngine) ReIndex() error {
	rs := re.db.GetDNSRuleSets()
	re.db.ClearDnsHostRules()
	for i := range rs {
		//		re.db.RemoveCategoryFromDnsHostRules(rs[i].CategoryId)
		rules := re.db.GetDNSRules(rs[i].RuleSetId)
		if rules != nil {
			for _, rule := range *rules {
				name := rule
				wildcard := false
				if name[:2] == "*." {
					wildcard = true
					name = rule[2:]
				}

				update := false
				hr := re.db.GetDnsHostRule(name)
				if hr == nil {
					hr = &db.DNSHostRule{
						Name:               name,
						WildcardCategories: make([]string, 0),
						ExactCategories:    make([]string, 0),
						DomScanCategories:  make([]string, 0),
					}
				}
				if wildcard {
					if !slices.Contains(hr.WildcardCategories, rs[i].CategoryId) {
						update = true
						hr.WildcardCategories = append(hr.WildcardCategories, rs[i].CategoryId)
					}
				} else {
					if !slices.Contains(hr.ExactCategories, rs[i].CategoryId) {
						update = true
						hr.ExactCategories = append(hr.ExactCategories, rs[i].CategoryId)
					}
				}
				if update {
					re.db.SetDnsHostRule(hr)
				}
			}
		}
	}
	return nil
}

func (re DNSRulesEngine) Test(name string) []string {
	matches := make([]string, 0)
	parts := strings.Split(name, ".")
	domscan := false
	for i := range parts {
		domain := strings.Join(parts[len(parts)-i-1:], ".")
		if domain != "" && domain != "." {
			hr := re.db.GetDnsHostRule(domain)
			if hr != nil {
				if i == len(parts)-1 {
					for _, cat := range hr.ExactCategories {
						if !slices.Contains(matches, cat) {
							matches = append(matches, cat)
						}
					}
					for _, cat := range hr.DomScanCategories {
						domscan = true
						if !slices.Contains(matches, cat) {
							matches = append(matches, cat)
						}
					}
				}
				for _, cat := range hr.WildcardCategories {
					if !slices.Contains(matches, cat) {
						matches = append(matches, cat)
					}
				}
			}
		}
	}

	if domscan == false {
		if re.settings.APIs.DomScan.Enabled && re.settings.APIs.DomScan.Services.WebSiteCategorization && re.settings.APIs.DomScan.Key != "" {
			req, err := http.NewRequest(
				"GET",
				fmt.Sprintf("https://domscan.net/v1/categorize?domain=%s", name),
				nil,
			)
			if err != nil {
				log.Fatal(err)
				return matches
			}

			req.Header.Set("X-API-Key", re.settings.APIs.DomScan.Key)

			client := &http.Client{}

			resp, err := client.Do(req)
			if err != nil {
				log.Fatal(err)
				return matches
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)

			var result Response

			err = json.Unmarshal(body, &result)
			if err != nil {
				log.Fatal(err)
				return matches
			}

			if len(result.Categories) > 0 {
				hr := re.db.GetDnsHostRule(name)
				if hr == nil {
					hr = &db.DNSHostRule{
						Name:               name,
						ExactCategories:    make([]string, 0),
						WildcardCategories: make([]string, 0),
						DomScanCategories:  make([]string, 0),
					}
				}
				for _, cat := range result.Categories {
					re.db.EnsureDNSCategory(&db.DNSCategory{
						CategoryName: cat.Category,
						CategoryId:   cat.CategoryID,
						Enabled:      true,
					})
					hr.DomScanCategories = append(hr.DomScanCategories, cat.CategoryID)
					matches = append(matches, cat.CategoryID)
					if cat.SubcategoryID != nil {
						re.db.EnsureDNSCategory(&db.DNSCategory{
							CategoryId:       *cat.SubcategoryID,
							CategoryName:     *cat.Subcategory,
							ParentCategoryId: &cat.CategoryID,
							Enabled:          true,
						})
						hr.DomScanCategories = append(hr.DomScanCategories, *cat.SubcategoryID)
						matches = append(matches, *cat.SubcategoryID)
					}
				}
				re.db.SetDnsHostRule(hr)

			}

		}
	}

	return matches
}

type category struct {
	CategoryName  string
	CategoryId    string
	SubCategories []category
	Enabled       bool
	Level         uint
}

func (re DNSRulesEngine) getCategoryHierarchy(cat category, cats []db.DNSCategory) []category {
	result := make([]category, 0)
	for _, c := range cats {
		if c.ParentCategoryId != nil && *c.ParentCategoryId == cat.CategoryId {
			sc := category{
				CategoryName: c.CategoryName,
				CategoryId:   c.CategoryId,
				Enabled:      c.Enabled,
			}
			sc.Level = cat.Level + 1
			sc.SubCategories = re.getCategoryHierarchy(sc, cats)
			result = append(result, sc)
		}
	}
	return result
}

func (re DNSRulesEngine) GetCategoryHierarchy(cat *category) []category {
	categories := re.db.GetDNSCategories()
	if cat == nil {
		tlc := make([]category, 0)
		for _, cat := range categories {
			if cat.ParentCategoryId == nil {
				c := category{
					CategoryName: cat.CategoryName,
					CategoryId:   cat.CategoryId,
					Enabled:      cat.Enabled,
					Level:        0,
				}
				c.SubCategories = re.getCategoryHierarchy(c, categories)
				tlc = append(tlc, c)
			}
		}

		return tlc
	}
	return re.getCategoryHierarchy(*cat, categories)
}
