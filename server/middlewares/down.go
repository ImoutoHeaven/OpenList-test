package middlewares

import (
	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"github.com/OpenListTeam/OpenList/v4/server/common"
	"github.com/gin-gonic/gin"
	"strings"
)

func PathParse(c *gin.Context) {
	rawPath := parsePath(c.Param("path"))
	common.GinWithValue(c, conf.PathKey, rawPath)
	c.Next()
}

func Down(verifyFunc func(string, string) error) func(c *gin.Context) {
	return func(c *gin.Context) {
		rawPath := c.Request.Context().Value(conf.PathKey).(string)
		// verify sign
		ctx, needSign, err := common.IsPathSignRequiredForRequest(c.Request.Context(), rawPath)
		if err != nil {
			common.ErrorPage(c, err, 500, true)
			return
		}
		c.Request = c.Request.WithContext(ctx)
		if needSign {
			s := c.Query("sign")
			err = verifyFunc(rawPath, strings.TrimSuffix(s, "/"))
			if err != nil {
				common.ErrorPage(c, err, 401)
				c.Abort()
				return
			}
		}
		c.Next()
	}
}

// TODO: implement
// path maybe contains # ? etc.
func parsePath(path string) string {
	return utils.FixAndCleanPath(path)
}
