## pre erquisites
## Python, R , R Studio

install.packages("sqliter")
install.packages("sqldf")
install.packages("magrittr")
install.packages("dplyr")
install.packages("rPython")
install.packages("rvest")
install.packages("stringr")
install.packages("tidyr")


library(dplyr)
library(sqldf)
library(rPython) ## don't need this just use the system call to execute the python script
library(rvest)
library(magrittr)
library(stringr)
library(tidyr)

system("C:\\Python27\\python.exe C:\\Python27\\vFeed\\vfeedcli.py  -u") ## i just use 27 as its home of vfeed files that is all

##connect to the vfeed

return_dataframe_from_table <- function(os_page_url, htmlnode) {
  os_page_url_df <- os_page_url %>%    html_nodes("#fwReportTable1") %>%    html_table()  %>% as.data.frame()
  return(os_page_url_df)
}

##

db <- dbConnect(SQLite(), dbname="vfeed.db") #connect to the vfeed



##lets mod the db and create a view which will join the cve_cpe to the nvd

## NO CREATE OR REPLACE BOO! USE DROP IF EXISTS INSTEAD

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
            FROM nvd_db
            LEFT JOIN cve_cpe
            ON cve_cpe.cveid=nvd_db.cveid
            ")

sqldf("SELECT * FROM V_vFeed",connection=db) 

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

Open_closed<-c("CS","CS","CS-SS","CS",
               "CS","CS","CS","OS",
               "CS","CS","CS","CS",
               "CS","CS","CS","CS",
               "CS","CS","CS")

os_page_url_df<-cbind(os_page_url_df,Open_closed)

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

?str_extract

support<-strsplit(Windows_10_df[16,1], "\n")[[1]]

support[[1]]
support[[2]]


reformat_support <- function(support_entry,support_type){
  
  support_entry<-strsplit(support_entry, "\n")[[1]]
    
  if(support_type=="Mainstream"){
    support_return <- support_entry[[1]]
  }else if(support_type=="Extended"){
    support_return <- support_entry[[2]]
  }else support_return <-"No Details"
  return(support_return)
}


Windows_10_df



add_supportTypes <- function(scraped_df){
  
  mainstream<-c("Mainstream",reformat_support(scraped_df[16,1],"Mainstream"))
  extended<-c("Extended",reformat_support(scraped_df[16,1],"Extended"))
  scraped_df<-rbind(scraped_df,mainstream)
  scraped_df<-rbind(scraped_df,extended)  
  return(scraped_df)
}

Windows_10_df<-add_supportTypes(Windows_10_df)


Windows_10_df[18,2]

"%w{3,9}?%s%d{1,2}?%s,%s%d{4}?"

s <- Windows_10_df[18,2]
s <- gsub( " *\\(.*?\\) *", "", s)
s <- gsub( " *\\[.*?\\] *", "", s)

month.abb.pattern <- paste(month.abb,collapse="|")

datetime.fmt <- "%w{3,9}?%s%d{1,2}?%s,%s%d{4}?"

strptime(substr(s, regexpr(month.abb.pattern, s), nchar(s)), datetime.fmt)

?str_replace
substr(Windows_10_df[18,2], regexpr(month.abb.pattern, s), nchar(s))


