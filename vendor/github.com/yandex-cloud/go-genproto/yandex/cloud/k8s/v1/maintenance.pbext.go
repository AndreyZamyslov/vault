// Code generated by protoc-gen-goext. DO NOT EDIT.

package k8s

import (
	duration "github.com/golang/protobuf/ptypes/duration"
	dayofweek "google.golang.org/genproto/googleapis/type/dayofweek"
	timeofday "google.golang.org/genproto/googleapis/type/timeofday"
)

type MaintenanceWindow_Policy = isMaintenanceWindow_Policy

func (m *MaintenanceWindow) SetPolicy(v MaintenanceWindow_Policy) {
	m.Policy = v
}

func (m *MaintenanceWindow) SetAnytime(v *AnytimeMaintenanceWindow) {
	m.Policy = &MaintenanceWindow_Anytime{
		Anytime: v,
	}
}

func (m *MaintenanceWindow) SetDailyMaintenanceWindow(v *DailyMaintenanceWindow) {
	m.Policy = &MaintenanceWindow_DailyMaintenanceWindow{
		DailyMaintenanceWindow: v,
	}
}

func (m *MaintenanceWindow) SetWeeklyMaintenanceWindow(v *WeeklyMaintenanceWindow) {
	m.Policy = &MaintenanceWindow_WeeklyMaintenanceWindow{
		WeeklyMaintenanceWindow: v,
	}
}

func (m *DailyMaintenanceWindow) SetStartTime(v *timeofday.TimeOfDay) {
	m.StartTime = v
}

func (m *DailyMaintenanceWindow) SetDuration(v *duration.Duration) {
	m.Duration = v
}

func (m *DaysOfWeekMaintenanceWindow) SetDays(v []dayofweek.DayOfWeek) {
	m.Days = v
}

func (m *DaysOfWeekMaintenanceWindow) SetStartTime(v *timeofday.TimeOfDay) {
	m.StartTime = v
}

func (m *DaysOfWeekMaintenanceWindow) SetDuration(v *duration.Duration) {
	m.Duration = v
}

func (m *WeeklyMaintenanceWindow) SetDaysOfWeek(v []*DaysOfWeekMaintenanceWindow) {
	m.DaysOfWeek = v
}
