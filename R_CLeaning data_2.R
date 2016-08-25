## pre erquisites
## Python, R , R Studio, DB browser

install.packages("sqliter")
install.packages("sqldf")
install.packages("magrittr")
install.packages("dplyr")
install.packages("rPython") ##don't need this really it does not play nice on Win only on my VM
install.packages("rvest")
install.packages("stringr")
install.packages("tidyr")
install.packages("lubridate")
install.packages("rtools")
install.packages("ggplot2")
install.packages("caret")
install.packages("plotrix")
install.packages("rattle")
install.packages("rpart.plot")
install.packages("party")
install.packages("partykit")
install.packages("cowplot")

library(rattle)
library(rpart.plot)
library(party)
library(partykit)
library(caret)
library(dplyr)
library(sqldf)
library(rPython) ## don't need this just use the system call to execute the python script
library(rvest)
library(magrittr)
library(stringr)
library(tidyr)
library(lubridate)
library(ggplot2)
library(stringi)
library(RColorBrewer)
library(reshape2)
library(caret)
library(plotrix)
library(cowplot)

##system("C:\\Python27\\python.exe C:\\Python27\\vFeed\\vfeedcli.py  -u") ## i just use 27 as its home of vfeed files that is all

system("C:\\Users\\Peter\\Anaconda2\\python.exe  C:\\Users\\Peter\\Anaconda2\\vFeed\\vfeedcli.py  -u")

exploits <-read.csv("https://raw.githubusercontent.com/offensive-security/exploit-database/master/files.csv")

##n_distinct(exploits$type)

##unique(exploits$type)

colnames(exploits)

##dos 
##local 
##remote 
##shellcode 
##webapps

unique(exploits$type)  

exploits %>%
  group_by(type) %>%
  summarise(count_by_type = n_distinct(id)) %>%
  arrange(count_by_type)

##type count_by_type
##(fctr)         (int)
##1 shellcode           568
##2     local          3217
##3       dos          5095
##4    remote          6332
##5   webapps         20837


##platform

exploits.by.platform<-exploits %>%
  group_by(platform) %>%
  summarise(count_by_platform = n_distinct(id)) %>%
  arrange(desc(count_by_platform)) %>% as.data.frame()

exploits.by.platform$count_by_platform<-as.numeric(exploits.by.platform$count_by_platform)

colnames(exploits.by.platform)

summary(exploits.by.platform)


ggplot(exploits.by.platform, aes(x = factor(platform), y = count_by_platform)) + 
  geom_bar(stat = "identity") + ##well thats not very fur f**kin usefull
  ggtitle("Count of Exploits by type") +
  theme(axis.text.x = element_text(angle = 90, hjust = 1, vjust = 0.5)) +
  xlab("Platform")+
  ylab("count by type")


hist(exploits.by.platform$count_by_platform)
##might want to limit that a bit maybe to limit this a bit

p <- ggplot(exploits.by.platform, aes(x=platform,y=log(count_by_platform)))+ geom_boxplot()

plot(p)

##colnames(exploits.by.platform)

exploits.by.platform %>%
  ##group_by(platform) %>%
  summarise(sd_count_by_all_platform = sd(count_by_platform),mean_count_by_all_platform = mean(count_by_platform),median_count_by_all_platform = median(count_by_platform),IQR_count_by_all_platform=IQR(count_by_platform)
              ) %>%
   as.data.frame()


##sd_count_by_all_platform mean_count_by_all_platform median_count_by_all_platform IQR_count_by_all_platform
##1                 2435.779                   563.2656                         12.5                     82.25




##


head(exploits.by.platform)


## Source: local data frame [64 x 2]

## platform count_by_type
## (fctr)         (int)
## 1       php         17748 ooh better tell Niall :)
## 2   windows          8044
## 3     linux          2404
## 4  multiple          2039
## 5       asp          1510
## 6  hardware          1130
## 7       cgi           696
## 8      unix           306
## 9       osx           293
## 10  lin_x86           233
## ..      ...           ...
## however this does not give us much  information

##connect to the vfeed




return_dataframe_from_table <- function(os_page_url, htmlnode) {
  os_page_url_df <- os_page_url %>%    html_nodes("#fwReportTable1") %>%    html_table()  %>% as.data.frame()
  return(os_page_url_df)
}

##

setwd("C:\\Users\\Peter\\Anaconda2\\vFeed")


db <- dbConnect(SQLite(), dbname="vfeed.db") #connect to the vfeed
##


## write the local dataframe to the SQLite database
dbWriteTable(db, "exploits", exploits)

##lets see if we can do anything with the exploits db

##lets mod the db and create a view which will join the cve_cpe to the nvd

## NO CREATE OR REPLACE BOO! USE DROP IF EXISTS INSTEAD

dbSendQuery(conn = db,"DROP VIEW IF EXISTS V_vFeed")

dbSendQuery(conn = db,
            "CREATE VIEW  V_vFeed
            AS
            SELECT
            nvd_db.cveid,
            nvd_db.date_published,
            nvd_db.date_modified,
            nvd_db.summary,
            nvd_db.cvss_base,
            nvd_db.cvss_impact,
            nvd_db.cvss_exploit,
            nvd_db.cvss_access_vector,
            nvd_db.cvss_access_complexity,
            nvd_db.cvss_authentication,
            nvd_db.cvss_confidentiality_impact,
            nvd_db.cvss_integrity_impact,
            nvd_db.cvss_availability_impact,
            cve_cpe.cpeid
            FROM nvd_db AS nvd_db
            LEFT JOIN cve_cpe
            ON cve_cpe.cveid=nvd_db.cveid
            ")
## maybe run a check
##sqldf("SELECT * FROM V_vFeed LIMIT 20",connection=db) 

##lets go and scrape some data
# https://www.netmarketshare.com/operating-system-market-share.aspx?qprid=10&qpcustomd=0

os_page_url <- read_html("https://www.netmarketshare.com/operating-system-market-share.aspx?qprid=10&qpcustomd=0")

#//*[@id="fwReportTable1"] xpath
##maybe functionalize this see below
##pass in url page and tag return a dataframe
## os_page_url_df <- os_page_url %>%
##     html_nodes("#fwReportTable1") %>%
##           html_table()  %>% as.data.frame()

os_page_url_df <- return_dataframe_from_table(os_page_url,"#fwReportTable1")

head(os_page_url_df)
desc(os_page_url_df)
colnames(os_page_url_df)
class(os_page_url_df)


##ooh yuck column names lets give them meaningfull names and do some clean up on the data

names(os_page_url_df) <- c("OS", "Market_Share")

os_page_url_df

##ooh yuck lots of odd characters (a bit like dublinR) in those columns

os_page_url_df$OS<-gsub(pattern = "Â", replacement = "", x = os_page_url_df$OS, ignore.case = T)

os_page_url_df$Market_Share<-gsub(pattern = "%", replacement = "", x = os_page_url_df$Market_Share, ignore.case = T)

os_page_url_df$Market_Share<- as.numeric(os_page_url_df$Market_Share)


##ok that data looks a bit better

##add a another column (Open Source and Closed Source Marker)

OS<-c("Windows 7","windows 10","Windows XP","Windows 8.1","Mac OS X 10.11","Linux","Windwows 8",
     "Mac OS X 10.10","Windows Vista","Mac OS X 10.9","Mac OS X 10.6","Mac OS X 10.8",
     "Mac OS X 10.7","Windows NT",
     "Mac OS X 10.12","Mac OS X 10.5","Windows 3.1","Mac OS X 10.4","Windows 2000","Mac OS X 10101",
     "Mac OS X (no version reported)"
     )

Source<-c('CS','CS','CS','CS','CS','OS','CS',
         'CS','CS','CS','CS','CS',
         'CS','CS',
         'CS','CS','CS','CS','CS','CS',
         'CS')


df.OS.Source = data.frame(OS,Source) 


#head(df.OS.Source,15)
## looks good


Mac0sx1011_page_url <- read_html("https://en.wikipedia.org/wiki/OS_X_El_Capitan")

##//*[@id="mw-content-text"]/table[1]
#table.infobox.vevent
#mw-content-text > table.infobox.vevent
##you are using Xpath, xpaths better than element its easier to read
return_dataframe_from_tablexpth <- function(os_page_url, htmlnode) {
  os_page_url_df <- os_page_url %>% html_nodes(xpath=htmlnode) %>%    html_table()  %>% as.data.frame() 
  return(os_page_url_df)
}


Mac0sx1011_page_url <- read_html("https://en.wikipedia.org/wiki/OS_X_El_Capitan")
#//*[@id="mw-content-text"]/table[1]
Windows81_page_url <- read_html("https://en.wikipedia.org/wiki/Windows_8.1")
##dont do this
##see below its more efficient


list_OS<-c('https://en.wikipedia.org/wiki/Windows_7','https://en.wikipedia.org/wiki/OS_X_El_Capitan',
           'https://en.wikipedia.org/wiki/Windows_8.1','https://en.wikipedia.org/wiki/Windows_XP',
           'https://en.wikipedia.org/wiki/Windows_10','https://en.wikipedia.org/wiki/OS_X_Yosemite',
           'https://en.wikipedia.org/wiki/Windows_Vista','https://en.wikipedia.org/wiki/OS_X_Mavericks',
           'https://en.wikipedia.org/wiki/Mac_OS_X_Lion','https://en.wikipedia.org/wiki/OS_X_Mountain_Lion',
           'https://en.wikipedia.org/wiki/Windows_3.1x','https://en.wikipedia.org/wiki/Mac_OS_X_Snow_Leopard',
           'https://en.wikipedia.org/wiki/Mac_OS_X_Leopard','https://en.wikipedia.org/wiki/Windows_2000'
)
list_OSName<-c('Windows 7','Mac OS X 10.11',
               'Windows 8.1','Windows XP',
               'Windows 10','Mac OS X 10.10',
               'Windows Vista','Mac OS X 10.9',
               'Mac OS X 10.7','Mac OS X 10.8',
               'Windows 3.1','Mac OS X 10.6',
               'Mac OS X 10.5','Windows 2000'
)

length(list_OS)
length(list_OSName)

list_OS[1]
list_OSName[[1]]

##this is not nice code
##at least functioalize this


counter<-1
for(name in list_OS){
  tryCatch({page_url <- read_html(name)
  X <-NULL
  X <- return_dataframe_from_tablexpth(page_url,'//*[@id="mw-content-text"]/table[1]')
  names(X) <- c("Col_1", "Col2")
  os_page_url_df$OS<-gsub(pattern = "Â", replacement = "", x = os_page_url_df$OS, ignore.case = T)
  os_page_url_df$OS<-gsub(pattern = "Â", replacement = "", x = os_page_url_df$OS, ignore.case = T)
  os_page_url_df$Market_Share<-gsub(pattern = "%", replacement = "", x = os_page_url_df$Market_Share, ignore.case = T)
  assign(paste(str_replace_all(list_OSName[[counter]]," ","_"), "df", sep = '_'), X)
  },
  error=function(cond) {
    message(paste("URL seems to be malformed", page_url))
    message("Here's the original error message:")
    message(cond)
    # Choose a return value in case of error
    return(NA)
  })
  counter <- counter+1
}


reformat_support <- function(support_entry,support_type){
  
  support_entry<-strsplit(support_entry, "\n")[[1]]
  
  if(support_type=="Mainstream"){
    counter<-0
    for(n in support_entry){
      counter<-counter+1
      if(grepl("Mainstream",support_entry[[counter]])){
        support_return<-support_entry[[counter]]
        break
      }
    }
  }else if(support_type=="Extended"){
    counter<-0
    for(n in support_entry){
      counter<-counter+1
      if(grepl("Extended",support_entry[[counter]])){
        support_return<-support_entry[[counter]]
        break
      }  
  }
    }else support_return <-"No Details"
  return(support_return)
}

add_supportTypes <- function(scraped_df){
  
  rwnum<-scraped_df[grepl("^Mainstream",scraped_df$Col_1),] %>% rownames() %>% as.numeric()
  
  if(length(rwnum)==0){
    rwnum<-scraped_df[grepl("Mainstream",scraped_df$Col_1),] %>% rownames() %>% as.numeric()
  }
  
  if(is.null(rwnum)){
    rwnum<-scraped_df[grepl("Mainstream",scraped_df$Col_1),] %>% rownames() %>% as.numeric()
  }
  
  mainstream<-c("Mainstream_DT",reformat_support(scraped_df[rwnum,1],"Mainstream"))
  extended<-c("Extended_DT",reformat_support(scraped_df[rwnum,1],"Extended"))
  scraped_df<-rbind(scraped_df,mainstream)
  scraped_df<-rbind(scraped_df,extended)  
  return(scraped_df)
}

#Windows_10_df$Col_1<-gsub(pattern = "\n", replacement = "", x = Windows_10_df$Col_1, ignore.case = T)
#Windows_10_df$Col_1<-gsub(pattern = "RTM:", replacement = "", x = Windows_10_df$Col_1, ignore.case = T)
#Windows_10_df[grepl("^Mainstream",Windows_10_df$Col_1),] %>% rownames() %>% as.numeric()


extract_dates<-function(support_types,support_type_dates){
  columnid<-2
  if(support_type_dates=="Mainstream_DT"){
  rowid<-support_types[grepl("^Mainstream_DT",support_types$Col_1),] %>% rownames() %>% as.numeric()
  }else if(support_type_dates=="Extended_DT"){
    rowid<-support_types[grepl("^Extended_DT",support_types$Col_1),] %>% rownames() %>% as.numeric()  
  } 
  date_return <- support_types[rowid,columnid]
  date_return <- gsub( " *\\(.*?\\) *", "", date_return)
  date_return <- gsub( " *\\[.*?\\] *", "", date_return)
  month.abb.pattern <- paste(month.abb,collapse="|")  
  date_return_processed<-mdy(substr(date_return, regexpr(month.abb.pattern, date_return), nchar(date_return))) ##use of lubridate much easier
  return(date_return_processed)
}

#Windows_10_df[c(-17,-18),]
#Windows_7_df

##loop over df's
##extract supports
##extract dates'
##add extract
##addsupport extracts

##functionalize
# 
# list_OS_tst<-c("Windows_10")
# list_OSName_tst<-c("Windows 10")
# extract_df<-Windows_10_df
# extract_df<-add_supportTypes(extract_df)
# 
# extract_df<-get(paste(str_replace_all(list_OSName_tst[[counter]]," ","_"), "df", sep = '_')  )
# 
# 
# 
# date_mainstream<-c("mainstream_date",as.character.Date(extract_dates(extract_df,"Mainstream_DT")))
# date_extended<-c("extended_date",as.character.Date(extract_dates(extract_df,"Extended_DT")))
# 
# extract_df<- rbind(extract_df,date_extended)
# extract_df<- rbind(extract_df,date_mainstream)

##extract_df$Col_1<-gsub(pattern = "RTM:", replacement = "", x = extract_df$Col_1, ignore.case = T)
##extract_df$Col2<-gsub(pattern = "RTM:", replacement = "", x = extract_df$Col2, ignore.case = T)
##extract_df<-add_supportTypes(extract_df)
##date_mainstream<-c("mainstream_date",as.character.Date(extract_dates(extract_df,"Mainstream_DT")))
##date_extended<-c("extended_date",as.character.Date(extract_dates(extract_df,"Extended_DT")))


counter<-1
for(name in list_OS){
  tryCatch({
  extract_df<-NULL  
    extract_df<-get(paste(str_replace_all(list_OSName[[counter]]," ","_"), "df", sep = '_')  )  ##get the object with this name
    extract_df$Col_1<-gsub(pattern = "RTM:", replacement = "", x = extract_df$Col_1, ignore.case = T)
    extract_df$Col2<-gsub(pattern = "RTM:", replacement = "", x = extract_df$Col2, ignore.case = T)
    
    extract_df<-add_supportTypes(extract_df)
      date_mainstream<-c("mainstream_date",as.character.Date(extract_dates(extract_df,"Mainstream_DT")))
    date_extended<-c("extended_date",as.character.Date(extract_dates(extract_df,"Extended_DT")))
  extract_df<- rbind(extract_df,date_extended)
    extract_df<- rbind(extract_df,date_mainstream)
      assign(paste(str_replace_all(list_OSName[[counter]]," ","_"), "df", sep = '_'), extract_df)
      },
  error=function(cond) {
    message(paste("problem building aggregate dataset",list_OSName[[counter]]))
    message("problem building aggregate dataset")
    message(cond)
    # Choose a return value in case of error
    return(NA)
  })
  counter<-counter+1
}


##loop through names, add a second column with OS
##
  


  
  # counter<-1
  # for(name in list_OS){
  #   try{
  #   extract_df<-NULL
  #   extract_df<-get(paste(str_replace_all(list_OSName[[counter]]," ","_"), "df", sep = '_')  )
  #     list2 <- rep(list_OSName[[counter]],length(list1))
  #       extract_df<-cbind(extract_df,list2)
  #     assign(paste(str_replace_all(list_OSName[[counter]]," ","_"), "df", sep = '_'), extract_df)
  #   counter<-counter+1  
  #   Total_Dataset<-rbind(Total_Dataset,extract_df)
  # }
  

list_OS
list_OSName


##linux distro

os_page_url_distro <- read_html("https://distrowatch.com/dwres.php?resource=popularity")

os_page_url_distro<-html_nodes(os_page_url_distro , xpath='//table') %>% .[[11]] %>% html_table() %>% as.data.frame()

colnames(os_page_url_distro)<-c("rank","distro","dwnloads")
  
## mobile

os_page_url_mobile <- read_html("https://www.netmarketshare.com/operating-system-market-share.aspx?qprid=10&qpcustomd=1")

os_page_url_mobile_df <- return_dataframe_from_table(os_page_url_mobile,"#fwReportTable1")

head(os_page_url_mobile_df)

str(os_page_url_mobile_df)

colnames(os_page_url_mobile_df)<-c("name","market_share")

os_page_url_mobile_df$market_share<-gsub(pattern = "%", replacement = "", x = os_page_url_mobile_df$market_share, ignore.case = T)
head(os_page_url_mobile_df)

# browser

os_page_url_browser <- read_html("https://www.netmarketshare.com/browser-market-share.aspx?qprid=2&qpcustomd=0")

os_page_url_browser_df <- return_dataframe_from_table(os_page_url_browser,"#fwReportTable1")

head(os_page_url_browser_df)

colnames(os_page_url_browser_df)<-c("name","market_share")

os_page_url_browser_df$market_share<-gsub(pattern = "%", replacement = "", x = os_page_url_browser_df$market_share, ignore.case = T)
head(os_page_url_browser_df)



##
####
##

os_page_url_db <- read_html("http://db-engines.com/en/ranking")

#body > table.body > tbody > tr:nth-child(1) > td:nth-child(2) > div > div.main > table.dbi

os_page_url_db_df <- html_nodes(os_page_url_db , xpath='//table') %>% .[[4]] %>% html_table(,fill=T) %>% as.data.frame()

#####
## read in file
####

colnames(os_page_url_db_df)

db_df<-os_page_url_db_df[4:nrow(os_page_url_db_df),1:8]

colnames(db_df)<- c('this month rank','previous month rank','-2 months previous  rank','DBMS','Database Model','this months score','previous months score','-2 months previous months score')

head(db_df)

# Detailed vendor-provided information available
db_df$DBMS<-gsub(pattern = "Detailed vendor-provided information available", replacement = "", x = db_df$DBMS, ignore.case = T)

# read in the detailed 

head(db_df)

tot_dbscore<-sum(as.numeric(db_df[,6]))

db_df$pct_dbscore<-(as.numeric(db_df[,6])/tot_dbscore)*100

head(db_df)

###
#####
#####
###


ios_share <-read.csv("C:\\Users\\Peter\\Documents\\GitHub\\a7b2aa37aba45fe4a7c7302fa4ec9525fc86f709\\ios_share.csv")

head(ios_share)

ios_df<-ios_share %>% select(OS,Total.Marketshare.by.both.platforms)

colnames(ios_df)<-colnames(os_page_url_mobile_df)

head(os_page_url_mobile_df,20)

os_page_url_mobile_df<-os_page_url_mobile_df[-c(2, 4, 19), ]

head(os_page_url_mobile_df,20)

os_page_url_mobile_df<-rbind(os_page_url_mobile_df,ios_df)

##

data_NVD_Supplementary <-read.csv("C:\\Users\\Peter\\Documents\\GitHub\\a7b2aa37aba45fe4a7c7302fa4ec9525fc86f709\\data_NVD_Supplementary.csv")

# head(data_NVD_Supplementary,30)

# colnames(data_NVD_Supplementary)

data_NVD_Supplementary$Extended.Support.End_dt<-data_NVD_Supplementary$Extended.Support.End

data_NVD_Supplementary$Mainstream.Support.End_dt<-data_NVD_Supplementary$Mainstream.Support.End

#os_page_url_df$Market_Share<-gsub(pattern = "%", replacement = "",
## x = os_page_url_df$Market_Share, ignore.case = T)

data_NVD_Supplementary$Mainstream.Support.End_dt<-gsub(pattern = "TBD", replacement = "",
                                  x = data_NVD_Supplementary$Mainstream.Support.End_dt, ignore.case = T)

data_NVD_Supplementary$Extended.Support.End_dt<-gsub(pattern = "TBD", replacement = "", 
                                 x = data_NVD_Supplementary$Extended.Support.End_dt, ignore.case = T)

data_NVD_Supplementary$Extended.Support.End_dt<-dmy(data_NVD_Supplementary$Extended.Support.End_dt)

data_NVD_Supplementary$Mainstream.Support.End_dt<-dmy(data_NVD_Supplementary$Mainstream.Support.End_dt)

data_NVD_Supplementary$Release_dt<-dmy(data_NVD_Supplementary$Release)

summary(data_NVD_Supplementary$Release_dt)

data_NVD_Supplementary$Release_dt<-as.Date(data_NVD_Supplementary$Release_dt)
str(data_NVD_Supplementary$Release_dt)

### lets now process data in NVD to make it easier to querey

data_NVD_Supplementary$Release_dt_timediff<-difftime(now(),data_NVD_Supplementary$Release_dt,units="days")

data_NVD_Supplementary$Mainstream.Support.End_dt_timediff<-difftime(now(),data_NVD_Supplementary$Mainstream.Support.End_dt,units="days")

data_NVD_Supplementary$Extended.Support.End_dt_timediff<-difftime(now(),data_NVD_Supplementary$Extended.Support.End_dt,units="days")

###data_NVD_Supplementary


## join to 


head(data_NVD_Supplementary,20)

##merge nvd_supplementary
# head(data_NVD_Supplementary) 
# head(os_page_url_mobile_df,20)
#pct_dbscore
# head(db_df[,c('DBMS','pct_dbscore')])
db_df$DBMS<-stri_trim(db_df$DBMS)
db_df$
data_NVD_Supplementary
os_page_url_mobile_df$name<-stri_trim(os_page_url_mobile_df$name)
data_NVD_Supplementary$Software<-stri_trim(data_NVD_Supplementary$Software)



data_NVD_Supplementary<-dplyr::left_join(data_NVD_Supplementary, os_page_url_mobile_df, by = c("Software"="name"))
data_NVD_Supplementary<-dplyr::left_join(data_NVD_Supplementary, db_df[,c('DBMS','pct_dbscore')], by = c("Software"="DBMS"))
colnames(data_NVD_Supplementary)
data_NVD_Supplementary$pct_dbscore<-as.numeric(data_NVD_Supplementary$pct_dbscore)
data_NVD_Supplementary$market_share<-as.numeric(data_NVD_Supplementary$market_share)
str(data_NVD_Supplementary)

##join browser data

data_NVD_Supplementary$market_share<-coalesce(data_NVD_Supplementary$market_share,data_NVD_Supplementary$pct_dbscore)


head(os_page_url_browser_df)

os_page_url_browser_df$market_share_browser<-as.numeric(os_page_url_browser_df$market_share)
os_page_url_browser_df$name<-stri_trim(os_page_url_browser_df$name)

data_NVD_Supplementary<-dplyr::left_join(data_NVD_Supplementary, os_page_url_browser_df[,c('name','market_share_browser')], by = c("Software"="name"))

data_NVD_Supplementary$market_share<-coalesce(data_NVD_Supplementary$market_share,data_NVD_Supplementary$market_share_browser)

## 

os_page_url_df$market_share_os<-as.numeric(os_page_url_df$Market_Share)
os_page_url_df$OS<-stri_trim(os_page_url_df$OS)
##

data_NVD_Supplementary<-dplyr::left_join(data_NVD_Supplementary, os_page_url_df[,c('OS','market_share_os')], by = c("Software"="OS"))

data_NVD_Supplementary$market_share<-coalesce(data_NVD_Supplementary$market_share,data_NVD_Supplementary$market_share_os)

##

market_share_linux<-os_page_url_df[OS=='Linux',c('market_share_os')]

## now multiply by distro watch figures

os_page_url_distro_downsloads_sum<-sum(os_page_url_distro$dwnloads)

os_page_url_distro$dwnloads_pct<-os_page_url_distro$dwnloads/os_page_url_distro_downsloads_sum

os_page_url_distro$dwnloads_pct.by.mrkt_share<-os_page_url_distro$dwnloads_pct*market_share_linux

os_page_url_distro$distro<-stri_trim(os_page_url_distro$distro)

data_NVD_Supplementary<-dplyr::left_join(data_NVD_Supplementary, os_page_url_distro[,c('distro','dwnloads_pct.by.mrkt_share')], by = c("Software"="distro"))


data_NVD_Supplementary$market_share<-coalesce(data_NVD_Supplementary$market_share,data_NVD_Supplementary$dwnloads_pct.by.mrkt_share)

data_NVD_Supplementary[64:74,]

##now join web browser market share data

web.server.market.share <-read.csv("C:\\Users\\Peter\\Documents\\GitHub\\a7b2aa37aba45fe4a7c7302fa4ec9525fc86f709\\web-server market share.csv")

# names(web.server.market.share)

# head(web.server.market.share)

data_NVD_Supplementary<-dplyr::left_join(data_NVD_Supplementary, web.server.market.share[,c('Version','Corrected.Version.Usage')], by = c("Software"="Version"))

data_NVD_Supplementary$market_share<-coalesce(data_NVD_Supplementary$market_share,data_NVD_Supplementary$Corrected.Version.Usage)




###


##now we have all supplementary material lets go and get exploit and vulnerability data from the supplementary df
##colnames(data_NVD_Supplementary)

data_NVD_Supplementary$cpe<-stri_trim(data_NVD_Supplementary$cpe)


db <- dbConnect(SQLite(), dbname="vfeed.db") #connect to the vfeed
##
## write the local dataframe to the SQLite database
# colnames(data_NVD_Supplementary)


dbSendQuery(conn = db,"DROP TABLE IF EXISTS data_NVD_Supplementary")

dbWriteTable(db, "data_NVD_Supplementary", data_NVD_Supplementary)

dbSendQuery(conn = db,"DROP TABLE IF EXISTS T_nvd_part_2")

dbSendQuery(conn = db,"CREATE TABLE T_nvd_part_2
            AS
            SELECT * FROM  T_VULNERABILITY_EXPLOITS WHERE cpeid in (SELECT CPE FROM data_NVD_Supplementary)")

##
#####
###

db <- dbConnect(SQLite(), dbname="vfeed.db") #connect to the vfeed

exploit.vulnerability.stats<-sqldf("SELECT * FROM T_nvd_part_2",connection=db) 

#head(exploit.vulnerability.stats,70)

data_NVD_Supplementary_exploits_vuln<-dplyr::left_join(data_NVD_Supplementary, exploit.vulnerability.stats, by = c("cpe"="cpeid"))

# head(data_NVD_Supplementary_exploits_vuln)
# colnames(data_NVD_Supplementary_exploits_vuln)
# 

data_NVD_Supplementary_exploits_vuln$exploit_cnt<-coalesce(as.numeric(data_NVD_Supplementary_exploits_vuln$exploit_cnt),0)
data_NVD_Supplementary_exploits_vuln$remote_exploit_cnt<-coalesce(as.numeric(data_NVD_Supplementary_exploits_vuln$remote_exploit_cnt),0)
data_NVD_Supplementary_exploits_vuln$local_exploit_cnt<-coalesce(as.numeric(data_NVD_Supplementary_exploits_vuln$local_exploit_cnt),0)
data_NVD_Supplementary_exploits_vuln$WEBAPPS_EXPLOIT_TYPE_cnt<-coalesce(as.numeric(data_NVD_Supplementary_exploits_vuln$WEBAPPS_EXPLOIT_TYPE_cnt),0)
data_NVD_Supplementary_exploits_vuln$DOS_EXPLOIT_TYPE_cnt<-coalesce(as.numeric(data_NVD_Supplementary_exploits_vuln$DOS_EXPLOIT_TYPE_cnt),0)
data_NVD_Supplementary_exploits_vuln$SHELLCODE_EXPLOIT_TYPE_cnt<-coalesce(as.numeric(data_NVD_Supplementary_exploits_vuln$SHELLCODE_EXPLOIT_TYPE_cnt),0)

##

data_NVD_Supplementary_exploits_vuln$cveid_cnt <- coalesce(as.numeric(data_NVD_Supplementary_exploits_vuln$cveid_cnt),0)
data_NVD_Supplementary_exploits_vuln$cvss_base_sum <- coalesce(as.numeric(data_NVD_Supplementary_exploits_vuln$cvss_base_sum),0)
data_NVD_Supplementary_exploits_vuln$cvss_impact_sum <- coalesce(as.numeric(data_NVD_Supplementary_exploits_vuln$cvss_impact_sum),0)
data_NVD_Supplementary_exploits_vuln$cvss_exploit_sum <- coalesce(as.numeric(data_NVD_Supplementary_exploits_vuln$cvss_exploit_sum),0)
data_NVD_Supplementary_exploits_vuln$local_access_sum  <- coalesce(as.numeric(data_NVD_Supplementary_exploits_vuln$local_access_sum),0)
data_NVD_Supplementary_exploits_vuln$adjacent_network_access_sum <-coalesce(as.numeric(data_NVD_Supplementary_exploits_vuln$adjacent_network_access_sum),0)
data_NVD_Supplementary_exploits_vuln$not_defined_network_access_sum  <-coalesce(as.numeric(data_NVD_Supplementary_exploits_vuln$not_defined_network_access_sum),0)
data_NVD_Supplementary_exploits_vuln$network_access_sum  <-coalesce(as.numeric(data_NVD_Supplementary_exploits_vuln$network_access_sum),0)
##
data_NVD_Supplementary_exploits_vuln$low_access_complexity_sum  <-coalesce(as.numeric(data_NVD_Supplementary_exploits_vuln$low_access_complexity_sum),0)
data_NVD_Supplementary_exploits_vuln$low_access_complexity_sum  <-coalesce(as.numeric(data_NVD_Supplementary_exploits_vuln$low_access_complexity_sum),0)
data_NVD_Supplementary_exploits_vuln$medium_access_complexity_sum   <-coalesce(as.numeric(data_NVD_Supplementary_exploits_vuln$medium_access_complexity_sum),0)
data_NVD_Supplementary_exploits_vuln$high_access_complexity_sum <-coalesce(as.numeric(data_NVD_Supplementary_exploits_vuln$high_access_complexity_sum),0)
data_NVD_Supplementary_exploits_vuln$not_defined_access_complexity_sum <-coalesce(as.numeric(data_NVD_Supplementary_exploits_vuln$not_defined_access_complexity_sum),0)
##
data_NVD_Supplementary_exploits_vuln$multiple_instance_cvss_authentication_sum <-coalesce(as.numeric(data_NVD_Supplementary_exploits_vuln$multiple_instance_cvss_authentication_sum),0)
data_NVD_Supplementary_exploits_vuln$not_defined_instance_cvss_authentication_sum <-coalesce(as.numeric(data_NVD_Supplementary_exploits_vuln$not_defined_instance_cvss_authentication_sum),0)
data_NVD_Supplementary_exploits_vuln$single_instance_cvss_authentication_sum <-coalesce(as.numeric(data_NVD_Supplementary_exploits_vuln$single_instance_cvss_authentication_sum),0)

##
data_NVD_Supplementary_exploits_vuln$partial_confiidentiality_impact_sum <-coalesce(as.numeric(data_NVD_Supplementary_exploits_vuln$partial_confiidentiality_impact_sum),0)
data_NVD_Supplementary_exploits_vuln$none_confiidentiality_impact_sum  <-coalesce(as.numeric(data_NVD_Supplementary_exploits_vuln$none_confiidentiality_impact_sum),0)

data_NVD_Supplementary_exploits_vuln$complete_confiidentiality_impact_sum  <-coalesce(as.numeric(data_NVD_Supplementary_exploits_vuln$complete_confiidentiality_impact_sum),0)
data_NVD_Supplementary_exploits_vuln$not_defined_confiidentiality_impact_sum  <-coalesce(as.numeric(data_NVD_Supplementary_exploits_vuln$not_defined_confiidentiality_impact_sum),0)

data_NVD_Supplementary_exploits_vuln$not_defined_cvss_integrity_impact_sum  <-coalesce(as.numeric(data_NVD_Supplementary_exploits_vuln$not_defined_cvss_integrity_impact_sum),0)
data_NVD_Supplementary_exploits_vuln$none_cvss_integrity_impact_sum  <-coalesce(as.numeric(data_NVD_Supplementary_exploits_vuln$none_cvss_integrity_impact_sum),0)
data_NVD_Supplementary_exploits_vuln$complete_cvss_integrity_impact_sum  <- coalesce(as.numeric(data_NVD_Supplementary_exploits_vuln$complete_cvss_integrity_impact_sum),0)
data_NVD_Supplementary_exploits_vuln$partial_cvss_integrity_impact_sum  <- coalesce(as.numeric(data_NVD_Supplementary_exploits_vuln$partial_cvss_integrity_impact_sum) ,0)
data_NVD_Supplementary_exploits_vuln$none_cvss_integrity_impact_sum  <- coalesce(as.numeric(data_NVD_Supplementary_exploits_vuln$none_cvss_integrity_impact_sum) ,0)
data_NVD_Supplementary_exploits_vuln$not_defined_cvss_integrity_impact_sum  <- coalesce(as.numeric(data_NVD_Supplementary_exploits_vuln$not_defined_cvss_integrity_impact_sum) ,0)
##


data_NVD_Supplementary_exploits_vuln$complete_cvss_availability_impact_sum   <- coalesce(as.numeric(data_NVD_Supplementary_exploits_vuln$complete_cvss_availability_impact_sum ) ,0)
##none_cvss_availability_impact_sum
data_NVD_Supplementary_exploits_vuln$none_cvss_availability_impact_sum   <- coalesce(as.numeric(data_NVD_Supplementary_exploits_vuln$none_cvss_availability_impact_sum ),0)
data_NVD_Supplementary_exploits_vuln$not_defined_cvss_availability_impact_sum   <- coalesce(as.numeric(data_NVD_Supplementary_exploits_vuln$not_defined_cvss_availability_impact_sum ),0)
data_NVD_Supplementary_exploits_vuln$partial_cvss_availability_impact_sum   <- coalesce(as.numeric(data_NVD_Supplementary_exploits_vuln$partial_cvss_availability_impact_sum ),0)
##str(data_NVD_Supplementary_exploits_vuln.desktop)

##
##no need for coalesce

data_NVD_Supplementary_exploits_vuln.desktop <- data_NVD_Supplementary_exploits_vuln %>% filter(Software.type=='OS_desktop'| Software.type=='Linux- OS') %>%
  select (
    Software,
    (exploit_cnt),                                 
    (remote_exploit_cnt),                           (local_exploit_cnt),                           
    (WEBAPPS_EXPLOIT_TYPE_cnt),                     (DOS_EXPLOIT_TYPE_cnt),                        
    (SHELLCODE_EXPLOIT_TYPE_cnt),                   (cveid_cnt),                                   
    (cvss_base_sum),                                (cvss_impact_sum),                             
    (cvss_exploit_sum),                             (network_access_sum),                          
    (local_access_sum),                             (adjacent_network_access_sum),                 
    (not_defined_network_access_sum),               (low_access_complexity_sum),                   
    (medium_access_complexity_sum),                 (high_access_complexity_sum),                  
    (not_defined_access_complexity_sum),            (none_cvss_authentication_sum),                
    (single_instance_cvss_authentication_sum),      (not_defined_instance_cvss_authentication_sum),
    (multiple_instance_cvss_authentication_sum),    (partial_confiidentiality_impact_sum),         
    (none_confiidentiality_impact_sum),             (complete_confiidentiality_impact_sum),        
    (not_defined_confiidentiality_impact_sum),      (not_defined_cvss_integrity_impact_sum),       
    (none_cvss_integrity_impact_sum),               (complete_cvss_integrity_impact_sum),          
    (partial_cvss_integrity_impact_sum),            (not_defined_cvss_availability_impact_sum),    
    (partial_cvss_availability_impact_sum),         (complete_cvss_availability_impact_sum),       
    (none_cvss_availability_impact_sum))

    
rownames(data_NVD_Supplementary_exploits_vuln.desktop)<-data_NVD_Supplementary_exploits_vuln.desktop$Software

data_NVD_Supplementary_exploits_vuln.desktop$Software<-NULL

# colnames(data_NVD_Supplementary_exploits_vuln.desktop)

# str(data_NVD_Supplementary_exploits_vuln.desktop)

data_NVD_Supplementary_exploits_vuln.desktop.scaled<-scale(data_NVD_Supplementary_exploits_vuln.desktop) %>% as.data.frame() 

data_NVD_Supplementary_exploits_vuln.desktop.scaled$names<-rownames(data_NVD_Supplementary_exploits_vuln.desktop.scaled)

##plot the heatmap

data_NVD_Supplementary_exploits_vuln.desktop.scaled.m <- melt(data_NVD_Supplementary_exploits_vuln.desktop.scaled)

# head(data_NVD_Supplementary_exploits_vuln.desktop.scaled.m)
# colnames(data_NVD_Supplementary_exploits_vuln.desktop.scaled.m)

## summary(data_NVD_Supplementary_exploits_vuln.desktop.scaled.dist.m)

##for clarity remove mac

data_NVD_Supplementary_exploits_vuln.desktop.scaled.m$names<-gsub(pattern = "Mac ", replacement = "", 
                x = data_NVD_Supplementary_exploits_vuln.desktop.scaled.m$names, ignore.case = T)

##coalesce NA's to -1 as nothing reported
## head(data_NVD_Supplementary_exploits_vuln.desktop.scaled.m)
## str(data_NVD_Supplementary_exploits_vuln.desktop.scaled.m)

data_NVD_Supplementary_exploits_vuln.desktop.scaled.m$value<-coalesce(as.numeric(data_NVD_Supplementary_exploits_vuln.desktop.scaled.m$value),-1)


p <- ggplot(data_NVD_Supplementary_exploits_vuln.desktop.scaled.m, aes(names,variable)) + 
            geom_tile(aes(fill = value),colour = "white") +
            scale_fill_gradient(low = "green",high = "red",name="normalized \n score")+
            ggtitle("Exploits and vulnerabilities \n for most Popular Desktop OS's")+
            theme(axis.text.x = element_text(angle = 90, hjust = 1))+
            xlab("Software")+
            ylab("Exploit and vulnerability measure (normalized scores)")
            


plot(p)

rownames(data_NVD_Supplementary_exploits_vuln.desktop.scaled)<-data_NVD_Supplementary_exploits_vuln.desktop.scaled$names

data_NVD_Supplementary_exploits_vuln.desktop.scaled$names<-NULL

data_NVD_Supplementary_exploits_vuln.desktop.scaled.dist<-dist(data_NVD_Supplementary_exploits_vuln.desktop.scaled, method = "euclidean") %>% as.matrix() %>% as.data.frame()

head(data_NVD_Supplementary_exploits_vuln.desktop.scaled.dist)

data_NVD_Supplementary_exploits_vuln.desktop.scaled.dist$names<-rownames(data_NVD_Supplementary_exploits_vuln.desktop.scaled.dist)

data_NVD_Supplementary_exploits_vuln.desktop.scaled.dist.m <- melt(data_NVD_Supplementary_exploits_vuln.desktop.scaled.dist)

## summary(data_NVD_Supplementary_exploits_vuln.desktop.scaled.dist.m)

## head(data_NVD_Supplementary_exploits_vuln.desktop.scaled.dist.m)

##for clarity remove mac

p.dist <- ggplot(data_NVD_Supplementary_exploits_vuln.desktop.scaled.dist.m, aes(names,variable)) + 
  geom_tile(aes(fill = value),colour = "white") +
  scale_fill_gradient(low = "white",high = "steelblue", name="distance based on exploit \n and vuln data") +
  ggtitle("Distance plot of \n exploits and vulnerabilities \n for most Popular Desktop OS's")+
  theme(axis.text.x = element_text(angle = 90, hjust = 1))+
  xlab("")+
  ylab("")
  
plot(p.dist)

## another way of doing this without a visulaization with row sums

#####
##
##
##
#data_NVD_Supplementary_exploits_vuln$Software.type
##
##
######

data_NVD_Supplementary_exploits_vuln.web.server <- data_NVD_Supplementary_exploits_vuln %>% filter(Software.type=='Web-server') %>%
  select (
    Software,
    (exploit_cnt),                                 
    (remote_exploit_cnt),                           (local_exploit_cnt),                           
    (WEBAPPS_EXPLOIT_TYPE_cnt),                     (DOS_EXPLOIT_TYPE_cnt),                        
    (SHELLCODE_EXPLOIT_TYPE_cnt),                   (cveid_cnt),                                   
    (cvss_base_sum),                                (cvss_impact_sum),                             
    (cvss_exploit_sum),                             (network_access_sum),                          
    (local_access_sum),                             (adjacent_network_access_sum),                 
    (not_defined_network_access_sum),               (low_access_complexity_sum),                   
    (medium_access_complexity_sum),                 (high_access_complexity_sum),                  
    (not_defined_access_complexity_sum),            (none_cvss_authentication_sum),                
    (single_instance_cvss_authentication_sum),      (not_defined_instance_cvss_authentication_sum),
    (multiple_instance_cvss_authentication_sum),    (partial_confiidentiality_impact_sum),         
    (none_confiidentiality_impact_sum),             (complete_confiidentiality_impact_sum),        
    (not_defined_confiidentiality_impact_sum),      (not_defined_cvss_integrity_impact_sum),       
    (none_cvss_integrity_impact_sum),               (complete_cvss_integrity_impact_sum),          
    (partial_cvss_integrity_impact_sum),            (not_defined_cvss_availability_impact_sum),    
    (partial_cvss_availability_impact_sum),         (complete_cvss_availability_impact_sum),       
    (none_cvss_availability_impact_sum))



rownames(data_NVD_Supplementary_exploits_vuln.web.server)<-data_NVD_Supplementary_exploits_vuln.web.server$Software

data_NVD_Supplementary_exploits_vuln.web.server$Software<-NULL

# colnames(data_NVD_Supplementary_exploits_vuln.desktop)

# str(data_NVD_Supplementary_exploits_vuln.desktop)

data_NVD_Supplementary_exploits_vuln.web.server.scaled<-scale(data_NVD_Supplementary_exploits_vuln.web.server) %>% as.data.frame() 

data_NVD_Supplementary_exploits_vuln.web.server.scaled$names<-rownames(data_NVD_Supplementary_exploits_vuln.web.server.scaled)

##plot the heatmap

data_NVD_Supplementary_exploits_vuln.web.server.scaled.m <- melt(data_NVD_Supplementary_exploits_vuln.web.server.scaled)



# head(data_NVD_Supplementary_exploits_vuln.web.server.scaled.m)
# colnames(data_NVD_Supplementary_exploits_vuln.web.server.scaled.m)

data_NVD_Supplementary_exploits_vuln.web.server.scaled.m$value<-coalesce(as.numeric(data_NVD_Supplementary_exploits_vuln.web.server.scaled.m$value),-1)

## summary(data_NVD_Supplementary_exploits_vuln.web.server.scaled.m)

p.web.browser <- ggplot(data_NVD_Supplementary_exploits_vuln.web.server.scaled.m, aes(names,variable)) + 
  geom_tile(aes(fill = value),colour = "white") + 
  scale_fill_gradient(low = "green",high = "red",name="normalized \n score")+
  ggtitle("Exploits and vulnerabilities \n for most Popular Web server's")+
  theme(axis.text.x = element_text(angle = 90, hjust = 1))+
  xlab("Software")+
  ylab("Exploit and vulnerability measure (normalized scores)")


plot(p.web.browser)


rownames(data_NVD_Supplementary_exploits_vuln.web.server.scaled)<-data_NVD_Supplementary_exploits_vuln.web.server.scaled$names

data_NVD_Supplementary_exploits_vuln.web.server.scaled$names<-NULL

data_NVD_Supplementary_exploits_vuln.web.server.scaled.m.dist<-dist(data_NVD_Supplementary_exploits_vuln.web.server.scaled, method = "euclidean") %>% as.matrix() %>% as.data.frame()

head(data_NVD_Supplementary_exploits_vuln.web.server.scaled.m.dist)

data_NVD_Supplementary_exploits_vuln.web.server.scaled.m.dist$names<-rownames(data_NVD_Supplementary_exploits_vuln.web.server.scaled.m.dist)

data_NVD_Supplementary_exploits_vuln.web.server.scaled.m.dist <- melt(data_NVD_Supplementary_exploits_vuln.web.server.scaled.m.dist)


p.web.browser.dist <- ggplot(data_NVD_Supplementary_exploits_vuln.web.server.scaled.m.dist, aes(names,variable)) + 
  geom_tile(aes(fill = value),colour = "white") +
  scale_fill_gradient(low = "white",high = "steelblue")

plot(p.web.browser.dist)


#####
##
##
#tablet and mobile
#dosame for tablet
## str(data_NVD_Supplementary_exploits_vuln)
##
#####

data_NVD_Supplementary_exploits_vuln.mobile.tablet <- data_NVD_Supplementary_exploits_vuln %>% filter(Software.type=='Mobile/tablet OS' & Software != 'Win /phone/tab') %>%
  select (
    Software,
    exploit_cnt,                                 
    remote_exploit_cnt,                           local_exploit_cnt,                           
    WEBAPPS_EXPLOIT_TYPE_cnt,                     DOS_EXPLOIT_TYPE_cnt,                        
    SHELLCODE_EXPLOIT_TYPE_cnt,                   cveid_cnt,                                   
    cvss_base_sum,                                cvss_impact_sum,                             
    cvss_exploit_sum,                             network_access_sum,                          
    local_access_sum,                             adjacent_network_access_sum,                 
    not_defined_network_access_sum,               low_access_complexity_sum,                   
    medium_access_complexity_sum,                 high_access_complexity_sum,                  
    not_defined_access_complexity_sum,            none_cvss_authentication_sum,                
    single_instance_cvss_authentication_sum,      not_defined_instance_cvss_authentication_sum,
    multiple_instance_cvss_authentication_sum,    partial_confiidentiality_impact_sum,         
    none_confiidentiality_impact_sum,             complete_confiidentiality_impact_sum,        
    not_defined_confiidentiality_impact_sum,      not_defined_cvss_integrity_impact_sum,       
    none_cvss_integrity_impact_sum,               complete_cvss_integrity_impact_sum,          
    partial_cvss_integrity_impact_sum,            not_defined_cvss_availability_impact_sum,    
    partial_cvss_availability_impact_sum,         complete_cvss_availability_impact_sum,       
    none_cvss_availability_impact_sum) 

str(data_NVD_Supplementary_exploits_vuln.mobile.tablet)

rownames(data_NVD_Supplementary_exploits_vuln.mobile.tablet)<-data_NVD_Supplementary_exploits_vuln.mobile.tablet$Software

head(data_NVD_Supplementary_exploits_vuln.mobile.tablet)

data_NVD_Supplementary_exploits_vuln.mobile.tablet$Software<-NULL

# colnames(data_NVD_Supplementary_exploits_vuln.desktop)

# str(data_NVD_Supplementary_exploits_vuln.mobile.tablet.scaled)

data_NVD_Supplementary_exploits_vuln.mobile.tablet.scaled<-scale(data_NVD_Supplementary_exploits_vuln.mobile.tablet) %>% as.data.frame()

data_NVD_Supplementary_exploits_vuln.mobile.tablet.scaled$names<-rownames(data_NVD_Supplementary_exploits_vuln.mobile.tablet.scaled)

?scale

##plot the heatmap
# head(data_NVD_Supplementary_exploits_vuln.mobile.tablet.scaled)

data_NVD_Supplementary_exploits_vuln.mobile.tablet.scaled.m <- melt(data_NVD_Supplementary_exploits_vuln.mobile.tablet.scaled)

# head(data_NVD_Supplementary_exploits_vuln.desktop.scaled.m)
# colnames(data_NVD_Supplementary_exploits_vuln.desktop.scaled.m)

data_NVD_Supplementary_exploits_vuln.mobile.tablet.scaled.m$value<-coalesce(as.numeric(data_NVD_Supplementary_exploits_vuln.mobile.tablet.scaled.m$value),-1)

p.mobile <- ggplot(data_NVD_Supplementary_exploits_vuln.mobile.tablet.scaled.m, aes(names,variable)) + 
  geom_tile(aes(fill = value),colour = "white") + 
  scale_fill_gradient(low = "green",high = "red",name="normalized \n score")+
  ggtitle("Exploits and vulnerabilities \n for most Popular Mobile OS's")+
  theme(axis.text.x = element_text(angle = 90, hjust = 1))+
  xlab("Software")+
  ylab("Exploit and vulnerability measure (normalized scores)")


plot(p.mobile)

data_NVD_Supplementary_exploits_vuln.mobile.tablet.scaled.dist<-dist(data_NVD_Supplementary_exploits_vuln.mobile.tablet.scaled, method = "euclidean") %>% as.matrix() %>% as.data.frame()

head(data_NVD_Supplementary_exploits_vuln.mobile.tablet.scaled.dist)

data_NVD_Supplementary_exploits_vuln.mobile.tablet.scaled.dist$names<-rownames(data_NVD_Supplementary_exploits_vuln.mobile.tablet.scaled.dist)

data_NVD_Supplementary_exploits_vuln.mobile.tablet.scaled.dist.m <- melt(data_NVD_Supplementary_exploits_vuln.mobile.tablet.scaled.dist)

p.mobile.dist <- ggplot(data_NVD_Supplementary_exploits_vuln.mobile.tablet.scaled.dist.m, aes(names,variable)) + 
  geom_tile(aes(fill = value),colour = "white") +
  scale_fill_gradient(low = "white",high = "steelblue")

##these are usefull for figuring out safe  and not so safe systems
##so what can we say android is just as fucked up as Mac ios

##what about browsers

#head(data_NVD_Supplementary_exploits_vuln)

data_NVD_Supplementary_exploits_vuln.browser <- data_NVD_Supplementary_exploits_vuln %>% filter(Software.type=='Browser' & market_share > 1.0) %>%
  select (
    Software,
    exploit_cnt,                                 
    remote_exploit_cnt,                           local_exploit_cnt,                           
    WEBAPPS_EXPLOIT_TYPE_cnt,                     DOS_EXPLOIT_TYPE_cnt,                        
    SHELLCODE_EXPLOIT_TYPE_cnt,                   cveid_cnt,                                   
    cvss_base_sum,                                cvss_impact_sum,                             
    cvss_exploit_sum,                             network_access_sum,                          
    local_access_sum,                             adjacent_network_access_sum,                 
    not_defined_network_access_sum,               low_access_complexity_sum,                   
    medium_access_complexity_sum,                 high_access_complexity_sum,                  
    not_defined_access_complexity_sum,            none_cvss_authentication_sum,                
    single_instance_cvss_authentication_sum,      not_defined_instance_cvss_authentication_sum,
    multiple_instance_cvss_authentication_sum,    partial_confiidentiality_impact_sum,         
    none_confiidentiality_impact_sum,             complete_confiidentiality_impact_sum,        
    not_defined_confiidentiality_impact_sum,      not_defined_cvss_integrity_impact_sum,       
    none_cvss_integrity_impact_sum,               complete_cvss_integrity_impact_sum,          
    partial_cvss_integrity_impact_sum,            not_defined_cvss_availability_impact_sum,    
    partial_cvss_availability_impact_sum,         complete_cvss_availability_impact_sum,       
    none_cvss_availability_impact_sum) 

str(data_NVD_Supplementary_exploits_vuln.browser)

rownames(data_NVD_Supplementary_exploits_vuln.browser)<-data_NVD_Supplementary_exploits_vuln.browser$Software

head(data_NVD_Supplementary_exploits_vuln.browser)

data_NVD_Supplementary_exploits_vuln.browser$Software<-NULL

# colnames(data_NVD_Supplementary_exploits_vuln.desktop)

# str(data_NVD_Supplementary_exploits_vuln.mobile.tablet.scaled)

data_NVD_Supplementary_exploits_vuln.browser.scaled<-scale(data_NVD_Supplementary_exploits_vuln.browser) %>% as.data.frame()

data_NVD_Supplementary_exploits_vuln.browser.scaled$names<-rownames(data_NVD_Supplementary_exploits_vuln.browser)

# ?scale

##plot the heatmap
# head(data_NVD_Supplementary_exploits_vuln.browser.scaled)

data_NVD_Supplementary_exploits_vuln.browser.scaled.m <- melt(data_NVD_Supplementary_exploits_vuln.browser.scaled)

# head(data_NVD_Supplementary_exploits_vuln.desktop.scaled.m)
# colnames(data_NVD_Supplementary_exploits_vuln.desktop.scaled.m)

data_NVD_Supplementary_exploits_vuln.browser.scaled.m$value<-coalesce(as.numeric(data_NVD_Supplementary_exploits_vuln.browser.scaled.m$value),-1)

p.browser <- ggplot(data_NVD_Supplementary_exploits_vuln.browser.scaled.m, aes(names,variable)) + 
  geom_tile(aes(fill = value),colour = "white") + 
  scale_fill_gradient(low = "green",high = "red",name="normalized \n score")+
  ggtitle("Exploits and vulnerabilities \n for most Popular Browser's")+
  theme(axis.text.x = element_text(angle = 90, hjust = 1))+
  xlab("Software")+
  ylab("Exploit and vulnerability measure (normalized scores)")

plot(p.browser)


### databases


data_NVD_Supplementary_exploits_vuln.database <- data_NVD_Supplementary_exploits_vuln %>% 
  filter(Software.type=='Database') %>%
  select (
    Software,
    exploit_cnt,                                 
    remote_exploit_cnt,                           local_exploit_cnt,                           
    WEBAPPS_EXPLOIT_TYPE_cnt,                     DOS_EXPLOIT_TYPE_cnt,                        
    SHELLCODE_EXPLOIT_TYPE_cnt,                   cveid_cnt,                                   
    cvss_base_sum,                                cvss_impact_sum,                             
    cvss_exploit_sum,                             network_access_sum,                          
    local_access_sum,                             adjacent_network_access_sum,                 
    not_defined_network_access_sum,               low_access_complexity_sum,                   
    medium_access_complexity_sum,                 high_access_complexity_sum,                  
    not_defined_access_complexity_sum,            none_cvss_authentication_sum,                
    single_instance_cvss_authentication_sum,      not_defined_instance_cvss_authentication_sum,
    multiple_instance_cvss_authentication_sum,    partial_confiidentiality_impact_sum,         
    none_confiidentiality_impact_sum,             complete_confiidentiality_impact_sum,        
    not_defined_confiidentiality_impact_sum,      not_defined_cvss_integrity_impact_sum,       
    none_cvss_integrity_impact_sum,               complete_cvss_integrity_impact_sum,          
    partial_cvss_integrity_impact_sum,            not_defined_cvss_availability_impact_sum,    
    partial_cvss_availability_impact_sum,         complete_cvss_availability_impact_sum,       
    none_cvss_availability_impact_sum) 



str(data_NVD_Supplementary_exploits_vuln.database)

rownames(data_NVD_Supplementary_exploits_vuln.database)<-data_NVD_Supplementary_exploits_vuln.database$Software

head(data_NVD_Supplementary_exploits_vuln.database)

data_NVD_Supplementary_exploits_vuln.database$Software<-NULL

# colnames(data_NVD_Supplementary_exploits_vuln.desktop)

# str(data_NVD_Supplementary_exploits_vuln.mobile.tablet.scaled)

data_NVD_Supplementary_exploits_vuln.database.scaled<-scale(data_NVD_Supplementary_exploits_vuln.database) %>% as.data.frame()

data_NVD_Supplementary_exploits_vuln.database.scaled$names<-rownames(data_NVD_Supplementary_exploits_vuln.database.scaled)

data_NVD_Supplementary_exploits_vuln.database.scaled.m <- melt(data_NVD_Supplementary_exploits_vuln.database.scaled)

data_NVD_Supplementary_exploits_vuln.database.scaled.m$value<-coalesce(as.numeric(data_NVD_Supplementary_exploits_vuln.database.scaled.m$value),-1)

p.database <- ggplot(data_NVD_Supplementary_exploits_vuln.database.scaled.m, aes(names,variable)) + 
  geom_tile(aes(fill = value),colour = "white") + 
  scale_fill_gradient(low = "green",high = "red",name="normalized \n score")+
  ggtitle("Exploits and vulnerabilities \n for most Popular Browser's")+
  theme(axis.text.x = element_text(angle = 90, hjust = 1))+
  xlab("Software")+
  ylab("Exploit and vulnerability measure (normalized scores)")

plot(p.database)

## so we can see here quiet quickly that MySQl worst performing, then oracle,SQL_Server

######
###
#
###
######

  # we now want to take the browser data 
  # Os
  # mobile OS
  # database
  # cvss_base_Sum
  # cvss_Impact_sum
  # cvss_exploit_sum
  #  get  the product of that
  #  scale (max min) within each tech branch
  #  once this is done lets look at the correlation between 
  #  scaled cvss product and market share
  #  

colnames(data_NVD_Supplementary_exploits_vuln)
  
data_NVD_Supplementary_exploits_vuln.database.mkshare <- data_NVD_Supplementary_exploits_vuln %>% 
  filter(Software.type=='Database') %>%
  select (Software,
    cvss_base_sum,cvss_impact_sum,                             
    cvss_exploit_sum,  Open_Closed_Src,                           
    Extended.Support.End_dt, Mainstream.Support.End_dt,
    Release_dt,Release_dt_timediff,                         
    Mainstream.Support.End_dt_timediff,Extended.Support.End_dt_timediff,            
    market_share
    )

#colnames(data_NVD_Supplementary_exploits_vuln.database)

data_NVD_Supplementary_exploits_vuln.database.mkshare$cvss_prodscore<-
  coalesce(data_NVD_Supplementary_exploits_vuln.database.mkshare$cvss_impact_sum,0)*coalesce(data_NVD_Supplementary_exploits_vuln.database.mkshare$cvss_exploit_sum,0)*coalesce(data_NVD_Supplementary_exploits_vuln.database.mkshare$cvss_base_sum,0) 
newrange=c(0,1)
data_NVD_Supplementary_exploits_vuln.database.mkshare$cvss_prodscore_scaled<-scale(data_NVD_Supplementary_exploits_vuln.database.mkshare$cvss_prodscore)
data_NVD_Supplementary_exploits_vuln.database.mkshare$cvss_prodscore_scaled

#?cor

## cor(data_NVD_Supplementary_exploits_vuln.database$cvss_prodscore_maxminscaled,
##    data_NVD_Supplementary_exploits_vuln.database$market_share
##     )

database.scatterplot<-ggplot(data_NVD_Supplementary_exploits_vuln.database.mkshare, aes(x=market_share, y=cvss_prodscore_scaled,shape=Open_Closed_Src)) +
  geom_point()      # Use hollow circles


### do the same for release dates

database.scatterplot.releasedate<-ggplot(data_NVD_Supplementary_exploits_vuln.database, aes(x=Release_dt_timediff, y=cvss_prodscore_scaled,shape=Open_Closed_Src)) +
  geom_point()

##for browser

data_NVD_Supplementary_exploits_vuln.browser.mkshare <- data_NVD_Supplementary_exploits_vuln %>% 
  filter(Software.type=='Browser') %>%
  select (Software,
          cvss_base_sum,cvss_impact_sum,                             
          cvss_exploit_sum,  Open_Closed_Src,                           
          Extended.Support.End_dt, Mainstream.Support.End_dt,
          Release_dt,Release_dt_timediff,                         
          Mainstream.Support.End_dt_timediff,Extended.Support.End_dt_timediff,            
          market_share
  )


data_NVD_Supplementary_exploits_vuln.browser.mkshare$cvss_prodscore<-
  coalesce(data_NVD_Supplementary_exploits_vuln.browser.mkshare$cvss_impact_sum,0)*coalesce(data_NVD_Supplementary_exploits_vuln.browser.mkshare$cvss_exploit_sum,0)*coalesce(data_NVD_Supplementary_exploits_vuln.browser.mkshare$cvss_base_sum,0) 

data_NVD_Supplementary_exploits_vuln.browser.mkshare$cvss_prodscore_scaled<-scale(data_NVD_Supplementary_exploits_vuln.browser.mkshare$cvss_prodscore)
data_NVD_Supplementary_exploits_vuln.browser.mkshare$cvss_prodscore_scaled

#?cor

## cor(data_NVD_Supplementary_exploits_vuln.database$cvss_prodscore_maxminscaled,
##    data_NVD_Supplementary_exploits_vuln.database$market_share
##     )

browser.scatterplot<-ggplot(data_NVD_Supplementary_exploits_vuln.browser.mkshare, aes(x=market_share, y=cvss_prodscore_scaled,shape=Open_Closed_Src)) +
  geom_point()      # Use hollow circles

### do the same for release dates

database.scatterplot.releasedate<-ggplot(data_NVD_Supplementary_exploits_vuln.database, aes(x=Release_dt_timediff, y=cvss_prodscore_maxminscaled,shape=Open_Closed_Src)) +
  geom_point()

##mobile OS

data_NVD_Supplementary_exploits_vuln.mobile.tablet.os.mkshare <- data_NVD_Supplementary_exploits_vuln %>% 
  filter(Software.type=='Mobile/tablet OS') %>%
  select (Software,
          cvss_base_sum,cvss_impact_sum,                             
          cvss_exploit_sum,  Open_Closed_Src,                           
          Extended.Support.End_dt, Mainstream.Support.End_dt,
          Release_dt,Release_dt_timediff,                         
          Mainstream.Support.End_dt_timediff,Extended.Support.End_dt_timediff,            
          market_share
  )


data_NVD_Supplementary_exploits_vuln.mobile.tablet.os.mkshare$cvss_prodscore<-
  coalesce(data_NVD_Supplementary_exploits_vuln.mobile.tablet.os.mkshare$cvss_impact_sum,0)*coalesce(data_NVD_Supplementary_exploits_vuln.mobile.tablet.os.mkshare$cvss_exploit_sum,0)*coalesce(data_NVD_Supplementary_exploits_vuln.mobile.tablet.os.mkshare$cvss_base_sum,0) 
data_NVD_Supplementary_exploits_vuln.mobile.tablet.os.mkshare$cvss_prodscore_scaled<-scale(data_NVD_Supplementary_exploits_vuln.mobile.tablet.os.mkshare$cvss_prodscore)
data_NVD_Supplementary_exploits_vuln.mobile.tablet.os.mkshare$cvss_prodscore_scaled



tabletphone.OS.scatterplot<-ggplot(data_NVD_Supplementary_exploits_vuln.mobile.tablet.os.mkshare, aes(x=market_share, y=cvss_prodscore_scaled,shape=Open_Closed_Src)) +
  geom_point()      # Use hollow circles

###
##### OS DEsktop
##

data_NVD_Supplementary_exploits_vuln.desktop.os.mkshare <- data_NVD_Supplementary_exploits_vuln %>% 
  filter(Software.type=='OS_desktop'| Software.type=='Linux- OS') %>%
  select (Software,
          cvss_base_sum,cvss_impact_sum,                             
          cvss_exploit_sum,  Open_Closed_Src,                           
          Extended.Support.End_dt, Mainstream.Support.End_dt,
          Release_dt,Release_dt_timediff,                         
          Mainstream.Support.End_dt_timediff,Extended.Support.End_dt_timediff,            
          market_share
  )


data_NVD_Supplementary_exploits_vuln.desktop.os.mkshare$cvss_prodscore<-
  coalesce(data_NVD_Supplementary_exploits_vuln.desktop.os.mkshare$cvss_impact_sum,0)*coalesce(data_NVD_Supplementary_exploits_vuln.desktop.os.mkshare$cvss_exploit_sum,0)*coalesce(data_NVD_Supplementary_exploits_vuln.desktop.os.mkshare$cvss_base_sum,0) 

data_NVD_Supplementary_exploits_vuln.desktop.os.mkshare$cvss_prodscore_scaled<-scale(data_NVD_Supplementary_exploits_vuln.desktop.os.mkshare$cvss_prodscore)
data_NVD_Supplementary_exploits_vuln.desktop.os.mkshare$cvss_prodscore_scaled


desktop.OS.scatterplot<-ggplot(data_NVD_Supplementary_exploits_vuln.desktop.os.mkshare, aes(x=market_share, y=cvss_prodscore_scaled,shape=Open_Closed_Src)) +
  geom_point()      # Use hollow circles

data_NVD_Supplementary_exploits_vuln.desktop.os.mkshare$Release_dt_timediff<-as.numeric(data_NVD_Supplementary_exploits_vuln.desktop.os.mkshare$Release_dt_timediff)

df.desktop<- data_NVD_Supplementary_exploits_vuln.desktop.os.mkshare %>% select(cvss_prodscore_scaled,market_share,Release_dt_timediff) 

cor(df.desktop, use="complete.obs", method="pearson")

qplot(Open_Closed_Src, log(cvss_prodscore), data = data_NVD_Supplementary_exploits_vuln.desktop.os.mkshare, 
      geom= "boxplot", fill = Open_Closed_Src)


###
#####
# Web browser
#####
###


data_NVD_Supplementary_exploits_vuln.web.server.mkshare <- data_NVD_Supplementary_exploits_vuln %>% 
  filter(Software.type=='Web-server') %>%
  select (Software,
          cvss_base_sum,cvss_impact_sum,                             
          cvss_exploit_sum,  Open_Closed_Src,                           
          Extended.Support.End_dt, Mainstream.Support.End_dt,
          Release_dt,Release_dt_timediff,                         
          Mainstream.Support.End_dt_timediff,Extended.Support.End_dt_timediff,            
          market_share
  ) %>% as.data.frame()


data_NVD_Supplementary_exploits_vuln.web.server.mkshare$cvss_prodscore<-
  coalesce(data_NVD_Supplementary_exploits_vuln.web.server.mkshare$cvss_impact_sum,0)*coalesce(data_NVD_Supplementary_exploits_vuln.web.server.mkshare$cvss_exploit_sum,0)*coalesce(data_NVD_Supplementary_exploits_vuln.web.server.mkshare$cvss_base_sum,0) 

data_NVD_Supplementary_exploits_vuln.web.server.mkshare$cvss_prodscore_scaled<-scale(data_NVD_Supplementary_exploits_vuln.web.server.mkshare$cvss_prodscore)
data_NVD_Supplementary_exploits_vuln.web.server.mkshare$cvss_prodscore_scaled

web_server.scatterplot<-ggplot(data_NVD_Supplementary_exploits_vuln.web.server.mkshare, aes(x=market_share, y=cvss_prodscore_scaled,shape=Open_Closed_Src)) +
  geom_point()      # Use hollow circles


plot(web_server.scatterplot)

data_NVD_Supplementary_exploits_vuln.web.server.mkshare$Release_dt_timediff<-as.numeric(data_NVD_Supplementary_exploits_vuln.web.server.mkshare$Release_dt_timediff)

df.web.browser<- data_NVD_Supplementary_exploits_vuln.web.server.mkshare %>% select(cvss_prodscore_scaled,market_share,Release_dt_timediff) 

cor(df.web.browser, use="complete.obs", method="pearson")

qplot(Open_Closed_Src, log(cvss_prodscore), data = data_NVD_Supplementary_exploits_vuln.web.server.mkshare, 
      geom= "boxplot", fill = Open_Closed_Src)

qplot(Open_Closed_Src, cvss_prodscore, data = data_NVD_Supplementary_exploits_vuln.web.server.mkshare, 
      geom= "boxplot", fill = Open_Closed_Src)







####
#######
#######
####

overalldset<-rbind(data_NVD_Supplementary_exploits_vuln.desktop.os.mkshare,
      data_NVD_Supplementary_exploits_vuln.mobile.tablet.os.mkshare) %>%
          rbind(data_NVD_Supplementary_exploits_vuln.browser.mkshare) %>%
              rbind(data_NVD_Supplementary_exploits_vuln.database.mkshare) %>%
                  rbind(data_NVD_Supplementary_exploits_vuln.web.server.mkshare)              

overalldset.marketshare.plot<-ggplot(overalldset, aes(x=market_share, y=cvss_prodscore_scaled,shape=Open_Closed_Src)) +
  geom_point()      # Use hollow circles


plot(overalldset.marketshare.plot)

## head(overalldset)

qplot(Open_Closed_Src, cvss_prodscore_scaled, data = overalldset, 
      geom= "boxplot", fill = Open_Closed_Src)
##
os.cs.scledprodscore.plt <- ggplot(overalldset, aes(x=Open_Closed_Src, y=cvss_prodscore_scaled)) + geom_boxplot() + 
  ggtitle("Boxplot of normalised \n cvss_prod_score within tech branch") + xlab("Open / Closed source") + 
    ylab("product of cvss scores with in branch") +
      scale_y_continuous(limits = c(-1, 1))

os.cs.logprodscore.plt <- ggplot(overalldset, aes(x=Open_Closed_Src, y = log(cvss_prodscore))) + geom_boxplot() + 
  ggtitle("Boxplot of log cvss_prod_score") + xlab("Open / Closed source") + 
  ylab("log of product of cvss scores") 


plot_grid(os.cs.scledprodscore.plt, os.cs.logprodscore.plt, labels = c("", ""), align = "h")


    
  



#
# colnames(overalldset)
# 

overalldset$Release_dt_timediff<-as.numeric(overalldset$Release_dt_timediff)


str(overalldset$Release_dt_timediff)

df<- overalldset %>% select(cvss_prodscore_scaled,market_share,Release_dt_timediff) 

cor(df, use="complete.obs", method="pearson")

df_os<- overalldset %>% filter(Open_Closed_Src=='OS') %>% select(cvss_prodscore_scaled,market_share,Release_dt_timediff) 

cormat_os<-cor(df_os, use="complete.obs", method="pearson")

df_cs<- overalldset %>% filter(Open_Closed_Src=='CS') %>% select(cvss_prodscore_scaled,market_share,Release_dt_timediff) 

cormat_cs<-cor(df_cs, use="complete.obs", method="pearson")

## lets build the correlation matrix

# Get lower triangle of the correlation matrix
get_lower_tri<-function(cormat){
  cormat[upper.tri(cormat)] <- NA
  return(cormat)
}
# Get upper triangle of the correlation matrix
get_upper_tri <- function(cormat){
  cormat[lower.tri(cormat)]<- NA
  return(cormat)
}


upper_tri_cs <- get_upper_tri(cormat_cs)
upper_tri_os <- get_upper_tri(cormat_os)

melted_cormat_cs <- melt(upper_tri_cs, na.rm = TRUE)
melted_cormat_os <- melt(upper_tri_os, na.rm = TRUE)

cormap.os<-ggplot(data = melted_cormat_os, aes(Var2, Var1, fill = value))+
  geom_tile(color = "white")+
  scale_fill_gradient2(low = "blue", high = "red", mid = "white", 
                       midpoint = 0, limit = c(-1,1), space = "Lab", 
                       name="Pearson\nCorrelation") +
  theme_minimal()+ 
  theme(axis.text.x = element_text(angle = 45, vjust = 1, 
                                   size = 12, hjust = 1))+
  coord_fixed()+
  ggtitle("Open-source")+
  xlab("")+
  ylab("")

cormap.cs<-ggplot(data = melted_cormat_cs, aes(Var2, Var1, fill = value))+
  geom_tile(color = "white")+
  scale_fill_gradient2(low = "blue", high = "red", mid = "white", 
                       midpoint = 0, limit = c(-1,1), space = "Lab", 
                       name="Pearson\nCorrelation") +
  theme_minimal()+ 
  theme(axis.text.x = element_text(angle = 45, vjust = 1, 
                                   size = 12, hjust = 1))+
  coord_fixed()+
  ggtitle("Closed-source")+
  xlab("")+
  ylab("")


plot_grid(cormap.os, cormap.cs, labels = c("", ""), align = "h")


##
###
#####
###
##

## head(overalldset)
## str(overalldset)


bble.overalldset<-overalldset

bble.overalldset$Days_since_end_of_support<-as.numeric(bble.overalldset$Mainstream.Support.End_dt_timediff)
bble.overalldset$Days_since_release<-as.numeric(bble.overalldset$Release_dt_timediff)


p.bubble.overall.dset <- ggplot(overalldset, aes(y=cvss_prodscore_scaled,
                        x=market_share,size=Days_since_end_of_support,colour=Open_Closed_Src))+
  geom_point()+
  xlab("Market share") + ylab("cvss_prodscore_scaled")+
  ggtitle("Bubble plot of market share, Software type, \n days since end of support")



###
#####
#######Lets run ANOVA on this
#####
##

anova.os.cs<-anova(lm(cvss_prodscore~c(Open_Closed_Src),data=overalldset))
summary(anova.os.cs)
anova.os.cs


plot.design(overalldset[,c('cvss_prodscore','Open_Closed_Src')])

##colnames(overalldset)

qplot(Open_Closed_Src, log(cvss_prodscore), data = overalldset, 
      geom= "boxplot", fill = Open_Closed_Src)


## head(overalldset)

qplot(Open_Closed_Src, cvss_prodscore_scaled, data = overalldset, 
      geom= "boxplot", fill = Open_Closed_Src)


##

overalldset2 <- overalldset %>% select(cvss_prodscore_scaled,Open_Closed_Src,market_share,Release_dt_timediff,Mainstream.Support.End_dt_timediff)  
dummies <- caret::dummyVars(cvss_prodscore_scaled ~ ., data = overalldset2) %>% as.data.frame()
overalldset3<-(predict(dummies,overalldset2)) %>% as.data.frame() %>%cbind(overalldset2$cvss_prodscore_scaled)
colnames(overalldset3)<-c("Open_Closed_Src.CS","Open_Closed_Src.OS","market_share",                      
                          "Release_dt_timediff","Mainstream.Support.End_dt_timediff","cvss_prodscore_scaled")
# check-same
# head(overalldset3)
# head(overalldset)

mod.lm.prodscore<-lm(cvss_prodscore_scaled~Open_Closed_Src.CS+Open_Closed_Src.OS+scale(market_share)+scale(Release_dt_timediff),data=overalldset3)
summary(mod.lm.prodscore)

library(rpart)
?rpart



mod.rpart.prodscore<-rpart(cvss_prodscore_scaled~Open_Closed_Src.CS+Open_Closed_Src.OS+scale(market_share)+scale(Release_dt_timediff),data=overalldset3)
summary(mod.rpart.prodscore)

fancyRpartPlot(mod.rpart.prodscore, main="Decision tree showing \n splitting criteria for CVSS prodscores")


plot(mod.rpart.prodscore)
text(mod.rpart.prodscore, use.n = TRUE)

rsq.rpart(mod.rpart.prodscore)

tmp <- printcp(mod.rpart.prodscore)
rsq.val <- 1-tmp[,c(3,4)] 

print(rsq.val)
##rel error =  1-R2 
##
rsq.val[nrow(rsq.val),] 
## rel error      xerror 
## 0.20671068 -0.01843364
1-0.20671068

mod.rpart.prodscore2<-rpart(cvss_prodscore_scaled~c(Open_Closed_Src)+scale(market_share)+scale(Release_dt_timediff)+scale(Mainstream.Support.End_dt_timediff)
                              ,data=overalldset)


summary(mod.rpart.prodscore2)

plot(mod.rpart.prodscore2)
text(mod.rpart.prodscore2, use.n = TRUE)

rsq.rpart(mod.rpart.prodscore)

tmp <- printcp(mod.rpart.prodscore)
rsq.val <- 1-tmp[,c(3,4)] 
print(rsq.val)


??fancyRpartPlot
fancyRpartPlot(mod.rpart.prodscore2)

